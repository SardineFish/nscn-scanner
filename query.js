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

[
    {
        $set: {
            any_available: {
                $or: [
                    { $gt: ["$scan.http.success", 0] },
                    { $gt: ["$scan.https.success", 0] },
                    { $gt: ["$scan.tcp.21.ftp.success", 0] },
                    { $gt: ["$scan.tcp.22.ssh.success", 0] },
                ]
            }
        }
    }
];

[
    {
        $match: {
            addr: "58.49.29.195",
        }
    },
    {
        $replaceRoot: {
            newRoot: {
                $mergeObjects: ["$$ROOT", {
                    vulns: {
                        $reduce: {
                            input: {
                                $map: {
                                    input: {
                                        $concatArrays: [
                                            { $objectToArray: "$web" },
                                            { $objectToArray: "$ssh" },
                                            { $objectToArray: "$ftp" },
                                        ],
                                    },
                                    as: "service",
                                    in: "$$service.v.vulns"
                                }
                            },
                            initialValue: [],
                            in: { $concatArrays: ['$$value', '$$this'] }
                        }
                    }
                }]
            }
        }
    },
    {
        $lookup: {
            from: "vulns",
            foreignField: "id",
            localField: "vulns",
            as: "vulns",
        }
    },
    {
        $replaceRoot: {
            newRoot: {
                $mergeObjects: ["$$ROOT", {
                    vulns: {
                        $arrayToObject: {
                            $map: {
                                input: "$vulns",
                                as: "vuln",
                                in: {
                                    k: "$$vuln.id",
                                    v: "$$vuln"
                                }
                            }
                        }
                    }
                }]
            }
        }
    }
];

[
    {
        $replaceRoot: {
            newRoot: {
                services: {
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
                            name: "$$service.v.name",
                            version: "$$service.v.version"
                        }
                    }
                }
            }
        }
    },
    {
        $unwind: "$services"
    },
    {
        $group: {
            _id: "$services.name",
            count: { $sum: 1 }
        }
    },
    {
        $sort: {
            count: -1
        }
    }
]