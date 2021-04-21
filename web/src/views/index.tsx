import React from "react";
import ReactDOM from "react-dom";
import "antd/dist/antd.min.css";
import "../css/style.scss";
import { HomePage } from "./home";
import { ServiceContext } from "../context/service";
import { API } from "../api/api";

const rootElement = document.querySelector("#root");

const App: React.FC = () =>
{
    return (<>
        <HomePage />
    </>)
};

// const App = (<>
//     <HomePage/>
// </>);

ReactDOM.render((<App/>), rootElement);