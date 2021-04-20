const esbuild = require("esbuild");
const fs = require("fs");
const sassPlugin = require("esbuild-plugin-sass");
// import { Plugin } from "esbuild";
// import esbuild from "esbuild";

const dev = process.argv.includes("--dev");
const watch = process.argv.find(arg => arg === "-w" || arg === "--watch") !== undefined;
const serveFiles = process.argv.find(arg => arg === "--serve" || arg === "-s") !== undefined;

fs.copyFileSync("./src/views/index.html", "./dist/index.html");

const serve = (config) => esbuild.serve({
    servedir: "./dist",
    host: "0.0.0.0",
    port: 5000,
}, config);

const buildFunc = serveFiles ? serve : esbuild.build;

buildFunc({
    entryPoints: [
        "src/views/index.tsx"
    ],
    outdir: "./dist/static/js",
    minify: !dev,
    watch: watch,
    sourcemap: true,
    bundle: true,
    plugins: [sassPlugin()]
});