# Third-party files served by `sift ui`

| File | Project | Version | Licence | Source | sha256 |
|---|---|---|---|---|---|
| `three.min.js` | three.js | r128 | MIT (`LICENSE.three.txt`) | https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js | `9274bbcec8d96168626c732b5d31c775aa8cfb7eaa0599bec0c175908a2c1ce2` |
| `three-GLTFLoader.js` | three.js add-on (`examples/js/loaders/GLTFLoader.js`) | r128 | MIT (`LICENSE.three.txt`) | https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/GLTFLoader.js | `5c15967ba830918a9caea6338712c994c354bccd4edc4569bde411c3ec06a3e6` |
| `three-SkeletonUtils.js` | three.js add-on (`examples/js/utils/SkeletonUtils.js`) | r128 | MIT (`LICENSE.three.txt`) | https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/utils/SkeletonUtils.js | `cc2e2e1a3183ab55169d185565f86f43f80c6dfafe73610d991e741ea990ac1a` |
| `kaykit-anims.glb` | KayKit Character Animations 1.1 (clips only, repacked) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `38e888d9c0ab1cfcbd2c1f7f21dbfb975b8d14149904691c64904059cf3bca3e` |
| `kaykit-props.glb` | KayKit Adventurers 2.0, Skeletons 1.1, Dungeon Pack 1.1 (selected models, merged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `8b45fded4beaf49d6311d6fa55226ab8fb8887062f302a7c81d77f6900602455` |
| `kaykit-knight.glb` | KayKit Adventurers 2.0 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `e484370733824a0740683e7f6040aae0d20e5efd4107dde1175d6a2ad7e2f199` |
| `kaykit-barbarian.glb` | KayKit Adventurers 2.0 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `d37824a1d6e8e8af57ef9ae4a87e9271c3986210fbc432fb44670749a577ccac` |
| `kaykit-mage.glb` | KayKit Adventurers 2.0 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `1f7d891bde50b879c70965f155b7b765b166dc3f8518e5abb86c0002f191a26e` |
| `kaykit-ranger.glb` | KayKit Adventurers 2.0 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `3a0b0166b9d61d58dcaaa739c3cc0538be46e00d2928dd5cb513d9a41770d2e9` |
| `kaykit-rogue.glb` | KayKit Adventurers 2.0 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `cae5d9b2f08d53f7b4ab2617d9f42f021c546eb10920455fdcd82a110867fae4` |
| `kaykit-rogue_hooded.glb` | KayKit Adventurers 2.0 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `e8f3233c6db190506fbef3ad855683e6cb8bd7350de637d923e14a08aef088dc` |
| `kaykit-skeleton_warrior.glb` | KayKit Skeletons 1.1 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `992d5cfd6beb5565c50f742587d492f2a2cfcdfb3ffe4435aa16461c6d0e54be` |
| `kaykit-skeleton_mage.glb` | KayKit Skeletons 1.1 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `aee903d0febd151dbc49a4784ad4135862b20c1b025bf433b98a08d52e5f7849` |
| `kaykit-skeleton_rogue.glb` | KayKit Skeletons 1.1 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `d5b8f074a78a9972af0966014905ea1df2e71d2c3495d37a211980e6343ee774` |
| `kaykit-skeleton_minion.glb` | KayKit Skeletons 1.1 (unchanged) by Kay Lousberg | - | CC0 1.0 | https://kaylousberg.itch.io (free tier), packed by `scripts/pack_kaykit.py` | `1fadbf1bc66fd7ce008eecd0ffccc8f8089e1c2887813559ca553680a738fece` |

Every file is served unchanged from this folder (no CDN, no network). A test verifies every hash. The add-ons are the same release as `three.min.js` and only extend
the global `THREE` (loading .glb models, cloning animated characters). The KayKit models are CC0
(public domain); credit is not required but given: Kay Lousberg, www.kaylousberg.com.
