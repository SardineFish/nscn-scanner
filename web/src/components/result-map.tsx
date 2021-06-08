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
        features: props.data
            .filter(data => data.geo.location.coordinates[0] !== 0 && data.geo.location.coordinates[1] !== 0)
            .map(data =>
            {
                data.count = Math.log(data.count);
                return data;
            })
            .map(data => ({
                type: "Feature",
                properties: data,
                geometry: data.geo.location,
            }))
    };
    
    return (<AMapScene
        className="map"
        onSceneLoaded={onload}
        map={{
            center: [104.052044, 28],
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
                values: [2, 10],
            }}
            color={{
                values: "#9dff8052"
            }}
            
        />
    </AMapScene>)
}