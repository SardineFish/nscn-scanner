import React, { useEffect, useRef, useState } from "react";
import { AMapScene, PointLayer } from "@antv/l7-react";
import { GaodeMap } from "@antv/l7-maps";
import { Scene } from "@antv/l7";
import { API, GeoStats } from "../api/api";

export function ResultMap(props: {data: GeoStats[]})
{
    const onload = (scene: Scene) =>
    {
        console.log(scene);
        scene.on("zoomchange", () =>
        {
            console.log(scene.getZoom());
        });
        scene.on("moveend", () =>
        {
            console.log(scene.getCenter());
        });
        scene.setMapStatus({
            dragEnable: true,
            zoomEnable: false
        });
    };

    const dataSource: GeoJSON.FeatureCollection = {
        type: "FeatureCollection",
        features: props.data.map(data => ({
            type: "Feature",
            properties: data,
            geometry: data.geo.location,
        }))
    };
    
    return (<AMapScene
        className="map"
        onSceneLoaded={onload}
        map={{
            center: [104.052044, 31.765476],
            zoom: 4.05,
            style: "amap://styles/ec237c7c388e464ef756af612f42523f",
            token: "157ffbd8ba3f68fcb611c1a067ef5bc7",
        }}

    >
        <PointLayer
            source={{
                data: dataSource,
            }}
            shape={{ values: "circle" }}
            size={{
                field: "count",
                values: [1, 30],
            }}
            color={{
                values: "#9dff8052"
            }}
            
        />
    </AMapScene>)
}