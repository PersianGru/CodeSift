# Third-party files served by `sift ui`

| File | Project | Version | Licence | Source | sha256 |
|---|---|---|---|---|---|
| `three.min.js` | three.js | r128 | MIT (`LICENSE.three.txt`) | https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js | `9274bbcec8d96168626c732b5d31c775aa8cfb7eaa0599bec0c175908a2c1ce2` |
| `three-CopyShader.js` | three.js add-on (`examples/js/shaders/CopyShader.js`) | r128 | MIT (`LICENSE.three.txt`) | https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/shaders/CopyShader.js | `6b5da4fe3b410286974590885f82fe4a446f25c728f7d6c888e2a2a331333949` |
| `three-LuminosityHighPassShader.js` | three.js add-on (`examples/js/shaders/LuminosityHighPassShader.js`) | r128 | MIT (`LICENSE.three.txt`) | https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/shaders/LuminosityHighPassShader.js | `00ed0682e61ca207d9c62298269472d6d4eedd9d33528400e7cbc633da8544da` |
| `three-EffectComposer.js` | three.js add-on (`examples/js/postprocessing/EffectComposer.js`) | r128 | MIT (`LICENSE.three.txt`) | https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/EffectComposer.js | `4fc320fa3185847797332bc2b0125b1a39b9cf5fc4170a2f180cfa54fb057a2b` |
| `three-RenderPass.js` | three.js add-on (`examples/js/postprocessing/RenderPass.js`) | r128 | MIT (`LICENSE.three.txt`) | https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/RenderPass.js | `57a549b2d6a947cddf0385a804dc70c3b2d155663d908e99e35d42274b3878be` |
| `three-ShaderPass.js` | three.js add-on (`examples/js/postprocessing/ShaderPass.js`) | r128 | MIT (`LICENSE.three.txt`) | https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/ShaderPass.js | `2e64890b8e4c4dafcfd796d5c84877f2ad36a101c83263211c500ec40eaf1240` |
| `three-UnrealBloomPass.js` | three.js add-on (`examples/js/postprocessing/UnrealBloomPass.js`) | r128 | MIT (`LICENSE.three.txt`) | https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/postprocessing/UnrealBloomPass.js | `1ed342b273e9b077a3e92e5caeecd45043f03071306c696564d5b53f0562dced` |
| `three-RoomEnvironment.js` | three.js add-on (`examples/js/environments/RoomEnvironment.js`) | r128 | MIT (`LICENSE.three.txt`) | https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/environments/RoomEnvironment.js | `94fd17363598048cb3faf3b3d7d663e561e8bc929b0162716f33424af30695ad` |

Every file is served unchanged from this folder (no CDN, no network). A test verifies every hash. The add-ons are the same release as `three.min.js` and only extend
the global `THREE` (bloom, studio-light reflections).
