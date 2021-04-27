const HtmlWebpackPlugin = require('html-webpack-plugin');
const Path = require("path");

/** @typedef {import("webpack").Configuration} */

/** @type {import("webpack").Configuration} */
module.exports = {
    entry: {
        "index": "./src/views/index.tsx"
    },
    output: {
        path: Path.resolve("./dist"),
        filename: "static/js/[name].bundle.js",
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js'],
        fallback: {
            "events": require.resolve("events/"),
            "stream": require.resolve("stream-browserify"),
        }
    },
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
            {
                test: /\.s[ac]ss$/i,
                use: [
                    // Creates `style` nodes from JS strings
                    "style-loader",
                    // Translates CSS into CommonJS
                    "css-loader",
                    // Compiles Sass to CSS
                    "sass-loader",
                ],
            },
            {
                test: /\.css$/i,
                use: [
                    "style-loader",
                    "css-loader",
                ]
            }
        ]
    },
    mode: "development",
    devtool: "source-map",
    devServer: {
        contentBase: "./dist",
        writeToDisk: true,
        open: false,
        host: "localhost",
        port: 5000,
        proxy: {
            "/api/**": {
                target: "http://localhost:3000/",
            }
        },
    },
    plugins: [
        new HtmlWebpackPlugin({
            filename: "index.html",
            template: "src/views/index.html",
            inject: true,
            minify: true,
            chunks: ["index"],
        })
    ]
}