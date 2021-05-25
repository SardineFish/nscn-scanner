import React, { useEffect, useState } from "react";
import { Col, Layout, Menu, Row, Statistic } from "antd";
import { StatsPreview } from "../components/stats-preview";
import { ResultSearch } from "../components/results-search";
import { Footer } from "../components/footer";
import { BrowserRouter as Router, Link, Switch, useHistory, Route } from "react-router-dom";
import { ResultMap } from "../components/result-map";

export const HomePage: React.FC = () =>
{
    return (<>
        <StatsPreview />
        <ResultSearch />
    </>)
};