[
    {
        $replaceRoot: {
            newRoot: {
                $mergeObjects: [
                    "$$ROOT",
                    {
                        addr_int: {
                            $map: {
                                input: {
                                    $split: [
                                        "$addr",
                                        "."
                                    ]
                                }, as: "slice", in: {
                                    $convert: { input: "$$slice", to: "long" }
                                }
                            }
                        }
                    }
                ]
            }
        }
    },
    {
        $set: {
            addr_int: {
                $add: [
                    {
                        $multiply: [
                            {
                                $arrayElemAt: [
                                    "$addr_int",
                                    0
                                ]
                            },
                            NumberLong(1 << 24)
                        ]
                    },
                    {
                        $multiply: [
                            {
                                $arrayElemAt: [
                                    "$addr_int",
                                    1
                                ]
                            },
                            NumberLong(1 << 16)
                        ]
                    },
                    {
                        $multiply: [
                            {
                                $arrayElemAt: [
                                    "$addr_int",
                                    2
                                ]
                            },
                            NumberLong(1 << 8)
                        ]
                    },
                    {
                        $arrayElemAt: [
                            "$addr_int",
                            3
                        ]
                    },
                ]
            }
        }
    }
];

[
    {
        $match: {
            addr_int: 974327653,
        }
    },
    { $skip: 0 },
    { $limit: 10 },
    {
        $project: {
            scan: "$$ROOT",
        }
    },
    {
        $lookup: {
            from: "analyse",
            localField: "scan.addr_int",
            foreignField: "addr_int",
            as: "analyse",
        }
    },
    {
        $project: {
            scan: "$scan",
            analyse: {
                $arrayElemAt: ["$analyse", 0]
            }
        }
    }
];

[
    {
        $match: {
            $or: [
                { "web.Nginx": { $gt: {} } },
                { "ftp.Nginx": { $gt: {} } },
                { "ssh.Nginx": { $gt: {} } },
            ]
        }
    },
    {
        $project: {
            "analyse": "$$ROOT"
        }
    },
    {
        $lookup: {
            from: "scan",
            localField: "analyse.addr_int",
            foreignField: "addr_int",
            as: "scan"
        }
    },
    {
        $project: {
            analyse: "$analyse",
            scan: { $arrayElemAt: ["$scan", 0] }
        }
    }
];

[
    {
        $replaceRoot: {
            newRoot: {
                vulns: {
                    $sum: {
                        $map: {
                            input: {
                                $concatArrays: [
                                    { $objectToArray: "$web" },
                                    { $objectToArray: "$ssh" },
                                    { $objectToArray: "$ftp" },
                                ],
                            },
                            as: "service",
                            in: {
                                $sum: { $size: "$$service.v.vulns" }
                            }

                        }
                    }
                    
                },
            }
        }
    },
    {
        $group: {
            _id: null,
            total_vulns: { $sum: "$vulns" }
        }
    }
];