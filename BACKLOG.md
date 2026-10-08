# Backlog

Real, finishable improvements - pick ONE, ship it end to end with tests.

## Features
- [ ] gold / mold map formats; MSVC LINK `/MAP`; IAR and Keil (armlink `--map`) - embedded
      users on those toolchains are the next biggest audience.
- [ ] Archive pull-in reasons: GNU maps start with "Archive member included to satisfy
      reference by file (symbol)" - surface it in link_where ("memcpy.o was pulled in
      because main.o references memcpy").
- [ ] Cross-reference table (`--cref`): who references a symbol, for "why is this kept?".
- [ ] Evaluate more script expressions (symbols defined earlier, `ORIGIN(r) + LENGTH(r)`,
      `SIZEOF`, `ADDR`) so MEMORY regions defined in terms of each other work.
- [ ] `link_stack`: estimate worst-case stack from `-fstack-usage` `.su` files + call graph.
- [ ] Watch mode for link_diff: compare against the previous build of the same name.

## Quality
- [ ] A Zephyr or Linux-kernel-sized map in the test corpus (performance and odd sections).
- [ ] Fuzz the GNU map parser with real maps from a few open-source firmware projects.
