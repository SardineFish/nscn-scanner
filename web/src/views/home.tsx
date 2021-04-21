import React, { useEffect, useState } from "react";
import { Col, Layout, Row, Statistic } from "antd";
import { StatsPreview } from "../components/stats-preview";
import { ResultSearch } from "../components/results-search";
import { Footer } from "../components/footer";

export const HomePage: React.FC = () =>
{

    return (
        <Layout>
            <Layout.Header>Header</Layout.Header>
            <Layout.Content>
                <StatsPreview />
                <ResultSearch/>
            </Layout.Content>
            <Layout.Footer className="page-footer"><Footer/></Layout.Footer>
        </Layout>
    )
};