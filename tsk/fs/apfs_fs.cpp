/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2019-2020 Brian Carrier.  All Rights reserved
 * Copyright (c) 2018-2019 BlackBag Technologies.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#include <cstring>
#include <stdexcept>

#include "apfs_fs.hpp"

// Look up an OID in the object map and return its physical address.
// Throws std::runtime_error if the OID is not found, rather than allowing
// a null/end iterator dereference which is undefined behavior.
static apfs_block_num checked_find_paddr(APFSObjectBtreeNode& obj_root,
                                         uint64_t oid) {
  const auto it = obj_root.find(oid);
  if (it == obj_root.end()) {
    throw std::runtime_error("APFS: root tree OID not found in object map");
  }
  return it->value->paddr;
}

APFSJObjTree::APFSJObjTree(const APFSPool& pool, apfs_block_num obj_omap,
                           uint64_t root_tree_oid,
                           const APFSFileSystem::crypto_info_t& crypto,
                           apfs_block_num fext_root)
    : _crypto{crypto},
      _obj_root{pool, obj_omap},
      _jobj_root{&_obj_root,
                 checked_find_paddr(_obj_root, root_tree_oid),
                 _crypto.key.get()},
      _root_tree_oid{root_tree_oid},
      _fext_root{fext_root} {}

APFSJObjTree::APFSJObjTree(const APFSFileSystem& vol)
    : APFSJObjTree{vol.pool(),
                   APFSOmap{vol.pool(), vol.fs()->omap_oid}.root_block(),
                   vol.rdo(), vol.crypto_info(), vol.fext_tree_block()} {}

// A node of the file extent tree of a sealed volume. Its keys and values have
// a fixed size, but its nodes may have no object header and, when they are
// not leaves, have the hash of the child after its address, so it is read
// here and not with the B-tree templates.
namespace {
class APFSFextNode : public APFSBlock {
 public:
  using APFSBlock::APFSBlock;

  inline const char* data() const noexcept { return _storage.data(); }
  inline size_t size() const noexcept { return _storage.size(); }
};

void fext_collect(const APFSPool& pool, apfs_block_num block, uint64_t id,
                  APFSJObject& jobj, int depth) {
  if (depth > 16) {
    throw std::runtime_error("APFS: file extent tree is too deep");
  }

  const auto node = pool.template get_block<APFSFextNode>(block, pool, block);
  const auto data = node->data();
  const auto size = node->size();
  const auto bn = reinterpret_cast<const apfs_btree_node*>(data);

  const bool leaf = bit_is_set(bn->flags, APFS_BTNODE_LEAF);
  const bool fixed = bit_is_set(bn->flags, APFS_BTNODE_FIXED_KV_SIZE);

  const size_t toc = sizeof(apfs_btree_node) + bn->table_space_offset;
  const size_t keys = toc + bn->table_space_length;
  const size_t vals_end =
      size - (bit_is_set(bn->flags, APFS_BTNODE_ROOT) ? sizeof(apfs_btree_info)
                                                      : 0);
  const size_t entry_size =
      fixed ? sizeof(apfs_btentry_fixed) : sizeof(apfs_btentry_variable);
  const size_t val_size = leaf ? sizeof(apfs_fext_tree_val) : sizeof(uint64_t);

  if (keys > size || bn->key_count > (keys - toc) / entry_size) {
    throw std::runtime_error("APFS: invalid file extent tree node");
  }

  // Key and value of an entry, checked to be inside the node
  const auto entry = [&](uint32_t i, const apfs_fext_tree_key*& key,
                         const char*& val) {
    size_t koff, voff;
    if (fixed) {
      const auto t = reinterpret_cast<const apfs_btentry_fixed*>(data + toc);
      koff = t[i].key_offset;
      voff = t[i].val_offset;
    } else {
      const auto t =
          reinterpret_cast<const apfs_btentry_variable*>(data + toc);
      koff = t[i].key_offset;
      voff = t[i].val_offset;
    }

    if (keys + koff + sizeof(apfs_fext_tree_key) > size || voff > vals_end ||
        vals_end - voff + val_size > size) {
      throw std::runtime_error("APFS: invalid file extent tree entry");
    }

    key = reinterpret_cast<const apfs_fext_tree_key*>(data + keys + koff);
    val = data + vals_end - voff;
  };

  for (uint32_t i = 0; i < bn->key_count; i++) {
    const apfs_fext_tree_key* key;
    const char* val;
    entry(i, key, val);

    if (key->private_id > id) {
      break;
    }

    if (leaf) {
      if (key->private_id == id) {
        const auto v = reinterpret_cast<const apfs_fext_tree_val*>(val);
        jobj.add_extent(key->logical_addr, v->phys_block_num,
                        bitfield_value(v->len_and_flags,
                                       APFS_FILE_EXTENT_LEN_BITS,
                                       APFS_FILE_EXTENT_LEN_SHIFT));
      }
      continue;
    }

    // The child has the keys from this one up to the next one: skip it if
    // the next one is still before the extents wanted.
    if (i + 1 < bn->key_count) {
      const apfs_fext_tree_key* next;
      const char* next_val;
      entry(i + 1, next, next_val);
      if (next->private_id < id) {
        continue;
      }
    }

    apfs_block_num child;
    std::memcpy(&child, val, sizeof(child));
    fext_collect(pool, child, id, jobj, depth + 1);
  }
}
}  // namespace

void APFSJObjTree::add_fext_extents(uint64_t oid, APFSJObject& jobj) const {
  if (_fext_root == 0 || !jobj.extents().empty()) {
    return;
  }

  fext_collect(_obj_root.pool(), _fext_root, oid, jobj, 0);
}

APFSJObject APFSJObjTree::obj(uint64_t oid) const {
  APFSJObject jobj{jobjs(oid)};
  add_fext_extents(oid, jobj);
  return jobj;
}

void APFSJObjTree::set_snapshot(uint64_t snap_xid) {
  _obj_root.snapshot(snap_xid);

  // This type isn't copyable or moveable, so we have to use in-place allocation
  // TODO(JTS): Refactor APFSObjects so that they can be move assigned
  // Resolve paddr before destroying _jobj_root so a throw leaves it intact.
  const apfs_block_num paddr = checked_find_paddr(_obj_root, _root_tree_oid);
  _jobj_root.~APFSJObjBtreeNode();
#ifdef HAVE_LIBOPENSSL
  new (&_jobj_root) APFSJObjBtreeNode(&_obj_root, paddr, _crypto.key.get());
#else
  new (&_jobj_root) APFSJObjBtreeNode(&_obj_root, paddr, nullptr);
#endif
}

APFSJObjTree::crypto::crypto(const APFSFileSystem::crypto_info_t& crypto) {
  if (crypto.unlocked) {
    key = std::make_unique<uint8_t[]>(0x20);
    std::memcpy(key.get(), crypto.vek, 0x20);
    password = crypto.password;

#ifdef HAVE_LIBOPENSSL
    decryptor = std::make_unique<aes_xts_decryptor>(
        aes_xts_decryptor::AES_128, key.get(), nullptr, APFS_CRYPTO_SW_BLKSIZE);
#endif
  }
}

APFSJObject::APFSJObject(const std::pair<jit, jit>& jobjs)
    : APFSJObject(jobjs.first, jobjs.second) {}

APFSJObject::APFSJObject(const jit& start, const jit& end) {
  std::for_each(start, end, [this](const auto& it) { this->add_entry(it); });
}

void APFSJObject::add_entry(const jit::value_type& e) {
  const auto key = e.key.template as<key_type>();

  switch (key->type()) {
    // Inode records
    case APFS_JOBJTYPE_INODE: {
      const auto value = e.value.template as<apfs_inode>();
      _inode = *value;

      // If the private_id is not the same as the oid then we're a clone
      _is_clone = (_inode.private_id != key->oid());

      // If there's more data than the size of the inode then we have xdata
      size_t e_offset = sizeof(apfs_inode);
      size_t e_size = e.value.count();
      // Need at least 4 bytes for start of extended fields (xf_blob_t)
      if (e_size > sizeof(apfs_inode) + 4) {
        // The xfield headers are right after the inode
        const auto xfield = reinterpret_cast<const apfs_xfield*>(value + 1);

        e_offset += 4;

        // Need at least 4 bytes for each x_field_t
        if (xfield->num_exts < (e_size - e_offset) / 4) {
          // sizeof(xf_blob_t) + number of extenteded fields * sizeof(x_field_t)
          e_offset += xfield->num_exts * 4;

          // The xfield data is after all of the xfield headers
          auto xfield_data =
              reinterpret_cast<const char*>(&xfield->entries[xfield->num_exts]);

          for (auto i = 0U; i < xfield->num_exts; i++) {
            const auto& ext = xfield->entries[i];

            switch (ext.type) {
              case APFS_XFIELD_TYPE_NAME:
                if((ext.len < 1) || (ext.len > e_size) || (e_offset > e_size - ext.len)) {
                  break;
                }
                _name = std::string(xfield_data, ext.len - 1);
                break;

              case APFS_XFIELD_TYPE_DSTREAM: {
                const auto ds =
                    reinterpret_cast<const apfs_dstream*>(xfield_data);

                _size = ds->size;
                _size_on_disk = ds->alloced_size;
                break;
              }
            }

            // The next data needs to be aligned properly
            xfield_data += (ext.len + 7) & 0xFFF8;
            e_offset += (ext.len + 7) & 0xFFF8;
          }
        }
      }
      break;
    }

    // Directory records
    case APFS_JOBJTYPE_DIR_RECORD: {
#pragma pack(push, 1)
      struct dir_record_key : key_type {
        uint32_t namelen_and_hash;
        char name[0];

        inline uint32_t name_len() const noexcept {
          return bitfield_value(namelen_and_hash, 10, 0);
        }

        inline uint32_t hash() const noexcept {
          return bitfield_value(namelen_and_hash, 22, 10);
        }
      };
#pragma pack(pop)
      static_assert(sizeof(dir_record_key) == 0x0C, "invalid struct padding");

      const auto k = e.key.template as<dir_record_key>();
      const auto value = e.value.template as<apfs_dir_record>();

      _children.emplace_back(
          child_entry{std::string(k->name, k->name_len() - 1U), *value});
      break;
    }

    // File extents
    case APFS_JOBJTYPE_FILE_EXTENT: {
      struct file_extent_key : key_type {
        uint64_t offset;
      };

      const auto k = e.key.template as<file_extent_key>();
      const auto value = e.value.template as<apfs_file_extent>();
      const auto len =
          bitfield_value(value->len_and_flags, APFS_FILE_EXTENT_LEN_BITS,
                         APFS_FILE_EXTENT_LEN_SHIFT);

      _extents.emplace_back(extent{k->offset, value->phys, len, value->crypto});

      break;
    }

    // Extended Attributes
    case APFS_JOBJTYPE_XATTR: {
      struct xattr_key : key_type {
        uint16_t name_len;
        char name[0];
      };

      const auto k = e.key.template as<xattr_key>();
      const auto value = e.value.template as<apfs_xattr>();

      if (value->flags & APFS_XATTR_FLAG_INLINE) {
#pragma pack(push, 1)
        struct ixattr : apfs_xattr {
          char data[0];
        };
#pragma pack(pop)

        const auto ix = e.value.template as<ixattr>();
        _inline_xattrs.emplace_back(inline_xattr{{k->name, k->name_len - 1U},
                                                 {ix->data, ix->xdata_len}});
        break;
      }

// Non-Resident XATTRs
#pragma pack(push, 1)
      struct nrattr : apfs_xattr {
        uint64_t xattr_obj_id;
        apfs_dstream dstream;
      };
#pragma pack(pop)
      static_assert(sizeof(nrattr) == 0x34, "misaligned structure");

      const auto nrx = e.value.template as<nrattr>();

      _nonres_xattrs.emplace_back(nonres_xattr{{k->name, k->name_len - 1U},
                                               nrx->xattr_obj_id,
                                               nrx->dstream.size,
                                               nrx->dstream.alloced_size,
                                               nrx->dstream.default_crypto_id});

      break;
    }
  };
}

APFSJObjTree::iterator APFSJObjTree::begin() const {
  return {this, APFS_ROOT_INODE_NUM};
}

APFSJObjTree::iterator APFSJObjTree::end() const { return {this}; }

APFSJObjTree::iterator::iterator(const APFSJObjTree* tree, uint64_t oid)
    : _tree{tree} {
  auto range = tree->jobjs(oid);
  _jobj = {range};
  tree->add_fext_extents(oid, _jobj);
  _next = std::move(range.second);
}

APFSJObjTree::iterator::iterator(const APFSJObjTree* tree) noexcept
    : _tree{tree} {}

APFSJObjTree::iterator& APFSJObjTree::iterator::operator++() {
  if (_next == _tree->_jobj_root.end()) {
    _next = {};
    _jobj = {};
    return (*this);
  }

  const auto key = _next->key.template as<APFSJObject::key_type>();

  auto end = std::find_if(
      _next,
      _tree->_jobj_root.end(), [oid = key->oid()](const auto& it) noexcept {
        const auto key = it.key.template as<APFSJObject::key_type>();
        return key->oid() > oid;
      });

  _jobj = {_next, end};
  _tree->add_fext_extents(key->oid(), _jobj);
  _next = std::move(end);

  return (*this);
}
