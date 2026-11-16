"""Pack the KayKit (CC0, Kay Lousberg) models that `sift ui`'s fantasy view uses into a few .glb files.

    python scripts/pack_kaykit.py ADVENTURERS.zip SKELETONS.zip ANIMATIONS.zip DUNGEON.zip

Reads the four free zips from kaylousberg.itch.io (never extracted to disk; member names are only
matched, never used as paths) and writes, into src/codesift/ui/static/vendor/:

  kaykit-<hero>.glb      the rigged characters, copied unchanged
  kaykit-anims.glb       only the animation clips the view plays, without meshes
  kaykit-props.glb       weapons and dungeon pieces merged into one file (one top-level node each)

Then update the hashes in vendor/THIRD_PARTY.md. Standard library only."""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parent.parent / "src" / "codesift" / "ui" / "static" / "vendor"

CHARACTERS = {
    "adventurers": ["Knight", "Barbarian", "Mage", "Ranger", "Rogue", "Rogue_Hooded"],
    "skeletons": ["Skeleton_Warrior", "Skeleton_Mage", "Skeleton_Rogue", "Skeleton_Minion"],
}
CLIPS = {
    "Rig_Medium_General.glb": [
        "Idle_A",
        "Idle_B",
        "Hit_A",
        "Death_A",
        "Death_A_Pose",
        "Spawn_Ground",
        "Interact",
        "Use_Item",
    ],
    "Rig_Medium_MovementBasic.glb": ["Walking_A", "Running_A"],
    "Rig_Medium_CombatMelee.glb": ["Melee_1H_Attack_Chop", "Melee_2H_Attack_Spin", "Melee_Block"],
    "Rig_Medium_CombatRanged.glb": [
        "Ranged_Magic_Spellcasting",
        "Ranged_Magic_Shoot",
        "Ranged_Bow_Release",
        "Ranged_Bow_Draw",
    ],
    "Rig_Medium_Simulation.glb": ["Cheering", "Sit_Floor_Idle"],
    "Rig_Medium_Special.glb": [
        "Skeletons_Awaken_Floor",
        "Skeletons_Idle",
        "Skeletons_Death",
        "Skeletons_Death_Pose",
        "Skeletons_Taunt",
        "Skeletons_Walking",
    ],
    "Rig_Medium_Tools.glb": ["Lockpicking"],
}
PROPS = {
    "adventurers": [
        "sword_1handed", "shield_badge_color", "axe_2handed", "staff", "bow_withString", "dagger", "wand",
        "spellbook_open", "quiver", "crossbow_1handed", "mug_full",
    ],
    "skeletons": ["Skeleton_Blade", "Skeleton_Staff", "Skeleton_Axe", "Skeleton_Shield_Small_A"],
    "dungeon": [
        "floor_tile_large", "floor_tile_large_rocks", "floor_dirt_large", "wall", "wall_arched", "wall_gated",
        "wall_doorway", "wall_corner", "wall_half", "pillar", "pillar_decorated", "column", "torch_mounted",
        "torch_lit", "chest_gold", "chest", "barrel_large", "barrel_small_stack", "crates_stacked",
        "banner_patternA_red", "banner_patternA_blue", "banner_shield_yellow", "banner_thin_green",
        "coin_stack_large", "candle_triple", "keyring_hanging", "sword_shield", "stairs", "table_medium",
        "rubble_large", "shelf_small_candles", "keg_decorated",
    ],
}  # fmt: skip


def read_glb(data: bytes) -> tuple[dict[str, Any], bytes]:
    magic, _version, _length = struct.unpack_from("<4sII", data, 0)
    if magic != b"glTF":
        raise ValueError("not a glb")
    off, doc, binary = 12, None, b""
    while off < len(data):
        size, kind = struct.unpack_from("<I4s", data, off)
        chunk = data[off + 8 : off + 8 + size]
        if kind == b"JSON":
            doc = json.loads(chunk)
        elif kind == b"BIN\x00":
            binary = chunk
        off += 8 + size
    if doc is None:
        raise ValueError("glb without JSON")
    return doc, binary


def write_glb(doc: dict[str, Any], binary: bytes) -> bytes:
    js = json.dumps(doc, separators=(",", ":")).encode()
    js += b" " * (-len(js) % 4)
    binary += b"\x00" * (-len(binary) % 4)
    total = 12 + 8 + len(js) + (8 + len(binary) if binary else 0)
    out = struct.pack("<4sII", b"glTF", 2, total) + struct.pack("<I4s", len(js), b"JSON") + js
    if binary:
        out += struct.pack("<I4s", len(binary), b"BIN\x00") + binary
    return out


class Builder:
    """Collects pieces of several glTF documents into one buffer and one document."""

    def __init__(self) -> None:
        self.blob = bytearray()
        self.doc: dict[str, Any] = {"asset": {"version": "2.0", "generator": "codesift pack_kaykit"}}
        self._images: dict[str, int] = {}

    def _list(self, key: str) -> list[Any]:
        items: list[Any] = self.doc.setdefault(key, [])
        return items

    def view(self, data: bytes, target: int | None = None, stride: int | None = None) -> int:
        while len(self.blob) % 4:
            self.blob.append(0)
        bv: dict[str, Any] = {"buffer": 0, "byteOffset": len(self.blob), "byteLength": len(data)}
        if target is not None:
            bv["target"] = target
        if stride:
            bv["byteStride"] = stride
        self.blob += data
        self._list("bufferViews").append(bv)
        return len(self.doc["bufferViews"]) - 1

    def image(self, data: bytes, mime: str) -> int:
        key = hashlib.sha256(data).hexdigest()
        if key not in self._images:
            self._list("images").append({"bufferView": self.view(data), "mimeType": mime})
            self._images[key] = len(self.doc["images"]) - 1
        return self._images[key]

    def finish(self) -> bytes:
        self.doc["buffers"] = [{"byteLength": len(self.blob)}]
        return write_glb(self.doc, bytes(self.blob))


def _slice(doc: dict[str, Any], buffers: list[bytes], view: int) -> bytes:
    bv = doc["bufferViews"][view]
    start, length = int(bv.get("byteOffset", 0)), int(bv["byteLength"])
    return buffers[int(bv.get("buffer", 0))][start : start + length]


def copy_accessor(b: Builder, doc: dict[str, Any], buffers: list[bytes], index: int) -> int:
    acc = dict(doc["accessors"][index])
    if "sparse" in acc:
        raise ValueError("sparse accessors are not used by these packs")
    bv = doc["bufferViews"][acc["bufferView"]]
    acc["bufferView"] = b.view(
        _slice(doc, buffers, acc["bufferView"]), bv.get("target"), bv.get("byteStride")
    )
    b._list("accessors").append(acc)
    return len(b.doc["accessors"]) - 1


def merge_props(
    b: Builder, name: str, doc: dict[str, Any], buffers: list[bytes], images: dict[str, bytes]
) -> None:
    """Append one prop document as a single named top-level node (its scene's nodes as children)."""
    acc_map: dict[int, int] = {}

    def acc(i: int) -> int:
        if i not in acc_map:
            acc_map[i] = copy_accessor(b, doc, buffers, i)
        return acc_map[i]

    tex_map: dict[int, int] = {}

    def tex(i: int) -> int:
        if i not in tex_map:
            src = doc["textures"][i]["source"]
            img = doc["images"][src]
            data = images[img["uri"]] if "uri" in img else _slice(doc, buffers, img["bufferView"])
            sampler = b._list("samplers")
            if not sampler:
                sampler.append(
                    {"magFilter": 9728, "minFilter": 9728}
                )  # crisp gradient atlas, as KayKit intends
            b._list("textures").append(
                {"source": b.image(data, img.get("mimeType", "image/png")), "sampler": 0}
            )
            tex_map[i] = len(b.doc["textures"]) - 1
        return tex_map[i]

    mat_map: dict[int, int] = {}

    def mat(i: int) -> int:
        if i not in mat_map:
            m = json.loads(json.dumps(doc["materials"][i]))
            pbr = m.get("pbrMetallicRoughness", {})
            if "baseColorTexture" in pbr:
                pbr["baseColorTexture"] = {"index": tex(pbr["baseColorTexture"]["index"])}
            for key in ("normalTexture", "occlusionTexture", "emissiveTexture", "metallicRoughnessTexture"):
                m.pop(key, None)
                pbr.pop(key, None)
            b._list("materials").append(m)
            mat_map[i] = len(b.doc["materials"]) - 1
        return mat_map[i]

    mesh_map: dict[int, int] = {}

    def mesh(i: int) -> int:
        if i not in mesh_map:
            src = doc["meshes"][i]
            prims = []
            for p in src["primitives"]:
                q: dict[str, Any] = {"attributes": {k: acc(v) for k, v in p["attributes"].items()}}
                if "indices" in p:
                    q["indices"] = acc(p["indices"])
                if "material" in p:
                    q["material"] = mat(p["material"])
                if "mode" in p:
                    q["mode"] = p["mode"]
                prims.append(q)
            b._list("meshes").append({"name": src.get("name", name), "primitives": prims})
            mesh_map[i] = len(b.doc["meshes"]) - 1
        return mesh_map[i]

    def node(i: int) -> int:
        src = doc["nodes"][i]
        n: dict[str, Any] = {
            k: src[k] for k in ("name", "translation", "rotation", "scale", "matrix") if k in src
        }
        if "mesh" in src:
            n["mesh"] = mesh(src["mesh"])
        kids = [node(c) for c in src.get("children", [])]
        if kids:
            n["children"] = kids
        b._list("nodes").append(n)
        return len(b.doc["nodes"]) - 1

    scene = doc["scenes"][doc.get("scene", 0)]
    kids = [node(i) for i in scene["nodes"]]
    b._list("nodes").append({"name": name, "children": kids})
    top = len(b.doc["nodes"]) - 1
    scenes = b._list("scenes")
    if not scenes:
        scenes.append({"nodes": []})
        b.doc["scene"] = 0
    scenes[0]["nodes"].append(top)


def pack_anims(z: zipfile.ZipFile) -> bytes:
    """Only the chosen clips, retargeted by bone name onto a flat list of bone nodes."""
    b = Builder()
    bones: dict[str, int] = {}
    members = {Path(n).name: n for n in z.namelist() if "/Rig_Medium/" in n and n.endswith(".glb")}
    for file, wanted in CLIPS.items():
        doc, binary = read_glb(z.read(members[file]))
        buffers = [binary]
        by_name = {a["name"]: a for a in doc.get("animations", [])}
        for clip in wanted:
            anim = by_name[clip]
            samplers, channels = [], []
            for ch in anim["channels"]:
                target = ch["target"]
                bone = doc["nodes"][target["node"]].get("name", "")
                if bone not in bones:
                    b._list("nodes").append({"name": bone})
                    bones[bone] = len(b.doc["nodes"]) - 1
                s = anim["samplers"][ch["sampler"]]
                samplers.append(
                    {
                        "input": copy_accessor(b, doc, buffers, s["input"]),
                        "output": copy_accessor(b, doc, buffers, s["output"]),
                        "interpolation": s.get("interpolation", "LINEAR"),
                    }
                )
                channels.append(
                    {"sampler": len(samplers) - 1, "target": {"node": bones[bone], "path": target["path"]}}
                )
            b._list("animations").append({"name": clip, "samplers": samplers, "channels": channels})
    b.doc["scenes"] = [{"nodes": list(bones.values())}]
    b.doc["scene"] = 0
    return b.finish()


def _gltf_members(z: zipfile.ZipFile) -> dict[str, str]:
    return {Path(n).name: n for n in z.namelist() if "/gltf/" in n.lower() and not n.endswith("/")}


def pack_props(zips: dict[str, zipfile.ZipFile]) -> bytes:
    b = Builder()
    for pack, names in PROPS.items():
        z = zips[pack]
        files = _gltf_members(z)
        for name in names:
            doc = json.loads(z.read(files[f"{name}.gltf"]))
            buffers = [z.read(files[Path(buf["uri"]).name]) for buf in doc["buffers"]]
            images = {
                img["uri"]: z.read(files[Path(img["uri"]).name])
                for img in doc.get("images", [])
                if "uri" in img
            }
            merge_props(b, name, doc, buffers, images)
    return b.finish()


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    zips = dict(
        zip(
            ["adventurers", "skeletons", "animations", "dungeon"],
            [zipfile.ZipFile(p) for p in argv],
            strict=True,
        )
    )
    written: dict[str, bytes] = {}
    for pack, names in CHARACTERS.items():
        z = zips[pack]
        members = {
            Path(n).name: n
            for n in z.namelist()
            if n.lower().endswith(".glb") and "/characters/" in n.lower()
        }
        for name in names:
            written[f"kaykit-{name.lower()}.glb"] = z.read(members[f"{name}.glb"])
    written["kaykit-anims.glb"] = pack_anims(zips["animations"])
    written["kaykit-props.glb"] = pack_props(zips)
    for name, data in written.items():
        read_glb(data)  # every file must parse back
        (OUT / name).write_bytes(data)
        print(f"{name:32} {len(data):>9,} bytes  sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"total {sum(len(d) for d in written.values()):,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
