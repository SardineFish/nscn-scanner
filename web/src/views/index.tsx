import React from "react";
import ReactDOM from "react-dom";
import "antd/dist/antd.min.css";
import "../css/style.scss";
import { HomePage } from "./home";
import { ServiceContext } from "../context/service";
import { API } from "../api/api";
import { BrowserRouter as Router, Link, Switch, useHistory, Route } from "react-router-dom";
import { Layout, Menu } from "antd";
import { Footer } from "../components/footer";
import { ResultSearch } from "../components/results-search";
import { StatsPreview } from "../components/stats-preview";
import { TaskPage } from "./task-page";

const rootElement = document.querySelector("#root");

const App: React.FC = () =>
{
    return (<Router>
        <Layout>
            <Layout.Header>
                <Menu theme="dark" mode="horizontal" defaultSelectedKeys={["home"]}>
                    <Menu.Item key="home">
                        <Link to="/">HOME</Link>
                    </Menu.Item>
                    <Menu.Item key="tasks">
                        <Link to="/tasks">DASHBOARD</Link>
                    </Menu.Item>
                </Menu>
            </Layout.Header>
            <Layout.Content>
                <Switch>
                    <Route path="/tasks">
                        <TaskPage />
                    </Route>
                    <Route path="/">
                        <HomePage />
                    </Route>
                </Switch>
            </Layout.Content>
            <Layout.Footer className="page-footer"><Footer /></Layout.Footer>
        </Layout>
    </Router>)
};

// const App = (<>
//     <HomePage/>
// </>);

ReactDOM.render((<App />), rootElement);