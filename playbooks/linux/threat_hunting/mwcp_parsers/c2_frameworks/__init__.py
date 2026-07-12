"""Cross-platform red-team/post-ex frameworks with real Linux agent builds (not a
Windows cross-compile afterthought): Sliver, Mythic, Merlin, Havoc, AdaptixC2, Pupy,
plus a generic Go-C2 structural heuristic for unnamed/custom frameworks."""
from . import adaptix, generic_go_c2, havoc, merlin, mythic, pupy, sliver

MODULES = (sliver, mythic, merlin, havoc, adaptix, pupy, generic_go_c2)
