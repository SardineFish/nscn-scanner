import GithubOutlined from "@ant-design/icons/lib/icons/GithubOutlined";
import React from "react";

export function Footer()
{
    return (<>
        <p>Copyright © 2015-{new Date().getFullYear()} SardineFish, All Rights Reserved</p>
        <p><a href="https://github.com/SardineFish/net-scanner"><GithubOutlined /> GitHub</a></p>
    </>) 
}