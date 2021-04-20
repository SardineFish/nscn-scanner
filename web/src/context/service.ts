import React from "react";
import { API } from "../api/api";

export const ServiceContext = React.createContext({
    api: API
});