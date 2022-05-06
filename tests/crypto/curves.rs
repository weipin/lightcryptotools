// Copyright 2022 Developers of the lightcryptotools project.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use lightcryptotools::bigint::BigInt;
use lightcryptotools::crypto::EllipticCurveParams;
use lightcryptotools::math::{Curve, Point};

pub(crate) fn nist_p256() -> EllipticCurveParams {
    EllipticCurveParams {
        curve: Curve {
            a: BigInt::from(-3),
            b: BigInt::from_hex(
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            )
            .unwrap(),
            p: BigInt::from_hex(
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            )
            .unwrap(),
        },
        base_point: Point {
            x: BigInt::from_hex(
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            )
            .unwrap(),
            y: BigInt::from_hex(
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            )
            .unwrap(),
        },
        base_point_order: BigInt::from_hex(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        )
        .unwrap(),
        cofactor: 1,
    }
}

pub(crate) fn brainpool_p256r1() -> EllipticCurveParams {
    EllipticCurveParams {
        curve: Curve {
            a: BigInt::from_hex(
                "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
            )
            .unwrap(),
            b: BigInt::from_hex(
                "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
            )
            .unwrap(),
            p: BigInt::from_hex(
                "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
            )
            .unwrap(),
        },
        base_point: Point {
            x: BigInt::from_hex(
                "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
            )
            .unwrap(),
            y: BigInt::from_hex(
                "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
            )
            .unwrap(),
        },
        base_point_order: BigInt::from_hex(
            "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
        )
        .unwrap(),
        cofactor: 1,
    }
}

pub(crate) fn brainpool_p320r1() -> EllipticCurveParams {
    EllipticCurveParams {
        curve: Curve {
            a: BigInt::from_hex(
                "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
            )
                .unwrap(),
            b: BigInt::from_hex(
                "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
            )
                .unwrap(),
            p: BigInt::from_hex(
                "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
            )
                .unwrap(),
        },
        base_point: Point {
            x: BigInt::from_hex(
                "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
            )
                .unwrap(),
            y: BigInt::from_hex(
                "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
            )
                .unwrap(),
        },
        base_point_order: BigInt::from_hex(
            "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311",
        )
            .unwrap(),
        cofactor: 1,
    }
}

pub(crate) fn brainpool_p384r1() -> EllipticCurveParams {
    EllipticCurveParams {
        curve: Curve {
            a: BigInt::from_hex(
                "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
            )
                .unwrap(),
            b: BigInt::from_hex(
                "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
            )
                .unwrap(),
            p: BigInt::from_hex(
                "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            )
                .unwrap(),
        },
        base_point: Point {
            x: BigInt::from_hex(
                "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
            )
                .unwrap(),
            y: BigInt::from_hex(
                "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
            )
                .unwrap(),
        },
        base_point_order: BigInt::from_hex(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
        )
            .unwrap(),
        cofactor: 1,
    }
}

pub(crate) fn brainpool_p512r1() -> EllipticCurveParams {
    EllipticCurveParams {
        curve: Curve {
            a: BigInt::from_hex(
                "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
            )
                .unwrap(),
            b: BigInt::from_hex(
                "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
            )
                .unwrap(),
            p: BigInt::from_hex(
                "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            )
                .unwrap(),
        },
        base_point: Point {
            x: BigInt::from_hex(
                "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
            )
                .unwrap(),
            y: BigInt::from_hex(
                "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
            )
                .unwrap(),
        },
        base_point_order: BigInt::from_hex(
            "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
        )
            .unwrap(),
        cofactor: 1,
    }
}

pub(crate) fn secp224r1() -> EllipticCurveParams {
    EllipticCurveParams {
        curve: Curve {
            a: BigInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE")
                .unwrap(),
            b: BigInt::from_hex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4")
                .unwrap(),
            p: BigInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001")
                .unwrap(),
        },
        base_point: Point {
            x: BigInt::from_hex("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21")
                .unwrap(),
            y: BigInt::from_hex("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34")
                .unwrap(),
        },
        base_point_order: BigInt::from_hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
        )
        .unwrap(),
        cofactor: 1,
    }
}

pub(crate) fn secp256r1() -> EllipticCurveParams {
    EllipticCurveParams {
        curve: Curve {
            a: BigInt::from_hex(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            )
            .unwrap(),
            b: BigInt::from_hex(
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            )
            .unwrap(),
            p: BigInt::from_hex(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            )
            .unwrap(),
        },
        base_point: Point {
            x: BigInt::from_hex(
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            )
            .unwrap(),
            y: BigInt::from_hex(
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            )
            .unwrap(),
        },
        base_point_order: BigInt::from_hex(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        )
        .unwrap(),
        cofactor: 1,
    }
}

pub(crate) fn secp384r1() -> EllipticCurveParams {
    EllipticCurveParams {
        curve: Curve {
            a: BigInt::from_hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            )
                .unwrap(),
            b: BigInt::from_hex(
                "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            )
                .unwrap(),
            p: BigInt::from_hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            )
                .unwrap(),
        },
        base_point: Point {
            x: BigInt::from_hex(
                "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            )
                .unwrap(),
            y: BigInt::from_hex(
                "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            )
                .unwrap(),
        },

        base_point_order: BigInt::from_hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        )
            .unwrap(),
        cofactor: 1,
    }
}

pub(crate) fn secp521r1() -> EllipticCurveParams {
    EllipticCurveParams {
        curve: Curve {
            a: BigInt::from_hex(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
            )
                .unwrap(),
            b: BigInt::from_hex(
                "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            )
                .unwrap(),
            p: BigInt::from_hex(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )
                .unwrap(),
        },
        base_point: Point {
            x: BigInt::from_hex(
                "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            )
                .unwrap(),
            y: BigInt::from_hex(
                "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            )
                .unwrap(),
        },

        base_point_order: BigInt::from_hex(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        )
            .unwrap(),
        cofactor: 1,
    }
}
