import React from "react";
import ReactDOM from "react-dom";
import "antd/dist/antd.css";
import "../css/style.sass";
import { HomePage } from "./home";

const rootElement = document.querySelector("#root");

const App = (<>
    <HomePage/>
</>);

ReactDOM.render(App, rootElement);