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
                                    $toInt: "$$slice"
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
                            1 << 24
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
                            1 << 16
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
                            1 << 8
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
]