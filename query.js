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
];

[
    {
        $group: {
            _id: "$geo.location",
            count: { $sum: 1 },
            geo: { $first: "$geo" },
        }
    }
];


[ // union analyse from scan
    {
        $match: {
            online: true,
        }
    },
    {
        $project: {
            addr: 1,
            addr_int: 1,
            last_update: 1,
            "results.port": 1,
            "results.result": 1
        }
    },
    {
        $replaceRoot: {
            newRoot: {
                addr: "$addr",
                addr_int: "$addr_int",
                last_update: "$last_update",
                ports: {
                    $reduce: {
                        input: {
                            $map: {
                                input: {
                                    $filter: {
                                        input: "$results",
                                        as: "result",
                                        cond: { $eq: ["$$result.result", "Ok"] }
                                    }
                                },
                                as: "result",
                                in: "$$result.port"
                            }
                        },
                        initialValue: [],
                        in: {$setUnion: ["$$value", ["$$this"]]}
                    }
                }
            }
        }
    },
    {
        $replaceRoot: {
            newRoot: {
                addr: "$addr",
                ports: "$ports",
                last_update: "$last_update",
                analyse: {
                    $cond: {
                        if: { $eq: ["$ports", []] },
                        then: null,
                        else: "$addr_int"
                    }
                }
            }
        }
    },
    {
        $lookup: {
            from: "analyse",
            localField: "analyse",
            foreignField: "addr_int",
            as: "analyse",
        }
    },
    {
        $project: {
            addr: "$addr",
            ports: "$ports",
            last_update: "$last_update",
            analyse: {
                $arrayElemAt: ["$analyse", 0],
            }
        }
    },
    {
        $replaceRoot: {
            newRoot: {
                addr: "$addr",
                ports: "$ports",
                last_update: "$last_update",
                services: {
                    $map: {
                        input: "$analyse.services",
                        as: "service",
                        in: {
                            name: "$$service.name",
                            version: "$$service.version",
                            vulns: { $size: "$$service.vulns" }
                        }
                    }
                },
            }
        }
    }
];

[
    {
        $match: {
            addr: "103.28.205.79",
        }
    },
    {
        $lookup: {
            from: "scan",
            localField: "addr_int",
            foreignField: "addr_int",
            as: "scan",
        }
    },
    {
        $project: {
            scan: { $arrayElemAt: ["$scan", 0] },
            services: "$services"
        }
    },
    {
        $replaceRoot: {
            newRoot: {
                addr: "$scan.addr",
                ports: {
                    $reduce: {
                        input: {
                            $map: {
                                input: {
                                    $filter: {
                                        input: "$scan.results",
                                        as: "result",
                                        cond: { $eq: ["$$result.result", "Ok"] }
                                    }
                                },
                                as: "result",
                                in: "$$result.port"
                            }
                        },
                        initialValue: [],
                        in: { $setUnion: ["$$value", ["$$this"]] }
                    }
                },
                services: {
                    $map: {
                        input: "$services",
                        as: "service",
                        in: {
                            name: "$$service.name",
                            version: "$$service.version",
                            vulns: { $size: "$$service.vulns" }
                        }
                    }
                },
            }
        }
    }
];

[
    {
        $match: {
            addr: "103.28.204.18",
        }
    },
    {
        $replaceRoot: {
            newRoot: {
                $mergeObjects: ["$$ROOT", {
                    vulns: {
                        $reduce: {
                            input: "$services",
                            initialValue: [],
                            in: { $concatArrays: ['$$value', '$$this.vulns'] }
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

           