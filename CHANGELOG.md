# Changelog

## 0.1.0 - 2026-10-08

First release.

- ELF reader (pyelftools): segments, sections with VMA and segment-derived LMA, symbols
  (ARM Thumb bit normalised, mapping symbols and SHN_ABS constants skipped).
- Map parsers for GNU ld (Memory Configuration, discarded sections, wrapped names,
  `load address`, `*fill*`, script patterns, assignments) and lld (fixed-width table).
- Linker-script parser: ENTRY, MEMORY (ORIGIN/ORG/o, LENGTH/LEN/l, K/M/G and simple
  arithmetic), SECTIONS with address, type, AT(), ALIGN, `> REGION`, `AT> REGION`, input
  rules with KEEP / EXCLUDE_FILE / SORT / archive:member patterns, assignments, PROVIDE,
  /DISCARD/; first-match rule resolution; a plain-English explanation.
- Tools: link_load, link_where, link_overlaps, link_biggest, link_diff, link_layout,
  link_script_explain, link_unload, link_sessions. Expected errors reach the agent as
  ToolError.
