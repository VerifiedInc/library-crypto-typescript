#!/bin/sh

# Need to remove the build directory otherwise will get a permissions conflict
rm -rf build/
npx typedoc src/index.ts
yarn build