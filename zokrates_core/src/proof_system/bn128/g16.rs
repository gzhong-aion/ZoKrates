use crate::ir;
use crate::proof_system::bn128::utils::bellman::Computation;
use crate::proof_system::bn128::utils::solidity::{
    SOLIDITY_G2_ADDITION_LIB, SOLIDITY_PAIRING_LIB, SOLIDITY_PAIRING_LIB_V2,
};
use crate::proof_system::ProofSystem;
use bellman::groth16::Parameters;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use zokrates_field::field::FieldPrime;

const G16_WARNING: &str = "WARNING: You are using the G16 scheme which is subject to malleability. See zokrates.github.io/reference/proving_schemes.html#g16-malleability for implications.";

pub struct G16 {}
impl ProofSystem for G16 {
    fn setup(&self, program: ir::Prog<FieldPrime>, pk_path: &str, vk_path: &str) {
        std::env::set_var("BELLMAN_VERBOSE", "0");

        println!("{}", G16_WARNING);

        let parameters = Computation::without_witness(program).setup();
        let parameters_file = File::create(PathBuf::from(pk_path)).unwrap();
        parameters.write(parameters_file).unwrap();
        let mut vk_file = File::create(PathBuf::from(vk_path)).unwrap();
        vk_file
            .write(serialize::serialize_vk(parameters.vk).as_ref())
            .unwrap();
    }

    fn generate_proof(
        &self,
        program: ir::Prog<FieldPrime>,
        witness: ir::Witness<FieldPrime>,
        pk_path: &str,
        proof_path: &str,
    ) -> bool {
        std::env::set_var("BELLMAN_VERBOSE", "0");

        println!("{}", G16_WARNING);

        let computation = Computation::with_witness(program, witness);
        let parameters_file = File::open(PathBuf::from(pk_path)).unwrap();

        let params = Parameters::read(parameters_file, true).unwrap();

        let proof = computation.clone().prove(&params);

        let mut proof_file = File::create(PathBuf::from(proof_path)).unwrap();
        write!(
            proof_file,
            "{}",
            serialize::serialize_proof(&proof, &computation.public_inputs_values())
        )
        .unwrap();
        true
    }

    fn export_solidity_verifier(&self, reader: BufReader<File>, is_abiv2: bool) -> String {
        let mut lines = reader.lines();

        let (mut template_text, solidity_pairing_lib) = if is_abiv2 {
            (
                String::from(CONTRACT_TEMPLATE_V2),
                String::from(SOLIDITY_PAIRING_LIB_V2),
            )
        } else {
            (
                String::from(CONTRACT_TEMPLATE),
                String::from(SOLIDITY_PAIRING_LIB),
            )
        };

        let gamma_abc_template = String::from("vk.gamma_abc[index] = Pairing.G1Point(points);"); //copy this for each entry

        //replace things in template
        let vk_regex = Regex::new(r#"(<%vk_[^i%]*%>)"#).unwrap();
        let vk_gamma_abc_len_regex = Regex::new(r#"(<%vk_gamma_abc_length%>)"#).unwrap();
        let vk_gamma_abc_index_regex = Regex::new(r#"index"#).unwrap();
        let vk_gamma_abc_points_regex = Regex::new(r#"points"#).unwrap();
        let vk_gamma_abc_repeat_regex = Regex::new(r#"(<%vk_gamma_abc_pts%>)"#).unwrap();
        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();

        for _ in 0..4 {
            let current_line: String = lines
                .next()
                .expect("Unexpected end of file in verification key!")
                .unwrap();
            let current_line_split: Vec<&str> = current_line.split("=").collect();
            assert_eq!(current_line_split.len(), 2);
            template_text = vk_regex
                .replace(template_text.as_str(), current_line_split[1].trim())
                .into_owned();
        }

        let current_line: String = lines
            .next()
            .expect("Unexpected end of file in verification key!")
            .unwrap();
        let current_line_split: Vec<&str> = current_line.split("=").collect();
        assert_eq!(current_line_split.len(), 2);
        let gamma_abc_count: i32 = current_line_split[1].trim().parse().unwrap();

        template_text = vk_gamma_abc_len_regex
            .replace(
                template_text.as_str(),
                format!("{}", gamma_abc_count).as_str(),
            )
            .into_owned();
        template_text = vk_input_len_regex
            .replace(
                template_text.as_str(),
                format!("{}", gamma_abc_count - 1).as_str(),
            )
            .into_owned();

        let mut gamma_abc_repeat_text = String::new();
        for x in 0..gamma_abc_count {
            let mut curr_template = gamma_abc_template.clone();
            let current_line: String = lines
                .next()
                .expect("Unexpected end of file in verification key!")
                .unwrap();
            let current_line_split: Vec<&str> = current_line.split("=").collect();
            assert_eq!(current_line_split.len(), 2);
            curr_template = vk_gamma_abc_index_regex
                .replace(curr_template.as_str(), format!("{}", x).as_str())
                .into_owned();
            curr_template = vk_gamma_abc_points_regex
                .replace(curr_template.as_str(), current_line_split[1].trim())
                .into_owned();
            gamma_abc_repeat_text.push_str(curr_template.as_str());
            if x < gamma_abc_count - 1 {
                gamma_abc_repeat_text.push_str("\n        ");
            }
        }
        template_text = vk_gamma_abc_repeat_regex
            .replace(template_text.as_str(), gamma_abc_repeat_text.as_str())
            .into_owned();

        let re = Regex::new(r"(?P<v>0[xX][0-9a-fA-F]{64})").unwrap();
        template_text = re.replace_all(&template_text, "uint256($v)").to_string();

        format!(
            "{}{}{}",
            SOLIDITY_G2_ADDITION_LIB, solidity_pairing_lib, template_text
        )
    }

    fn export_avm_verifier(&self, reader: BufReader<File>) -> String {
        CONTRACT_AVM_TEMPLATE.to_string()
    }
}

mod serialize {

    use crate::proof_system::bn128::utils::bellman::{
        parse_fr_json, parse_g1_hex, parse_g1_json, parse_g2_hex, parse_g2_json,
    };
    use bellman::groth16::{Proof, VerifyingKey};
    use pairing::bn256::{Bn256, Fr};

    pub fn serialize_vk(vk: VerifyingKey<Bn256>) -> String {
        format!(
            "vk.alpha = {}
    vk.beta = {}
    vk.gamma = {}
    vk.delta = {}
    vk.gamma_abc.len() = {}
    {}",
            parse_g1_hex(&vk.alpha_g1),
            parse_g2_hex(&vk.beta_g2),
            parse_g2_hex(&vk.gamma_g2),
            parse_g2_hex(&vk.delta_g2),
            vk.ic.len(),
            vk.ic
                .iter()
                .enumerate()
                .map(|(i, x)| format!("vk.gamma_abc[{}] = {}", i, parse_g1_hex(x)))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    pub fn serialize_proof(p: &Proof<Bn256>, inputs: &Vec<Fr>) -> String {
        format!(
            "{{
        \"proof\": {{
            \"a\": {},
            \"b\": {},
            \"c\": {}
        }},
        \"inputs\": [{}]
    }}",
            parse_g1_json(&p.a),
            parse_g2_json(&p.b),
            parse_g1_json(&p.c),
            inputs
                .iter()
                .map(parse_fr_json)
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

const CONTRACT_TEMPLATE_V2: &str = r#"
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.a = Pairing.G1Point(<%vk_a%>);
        vk.b = Pairing.G2Point(<%vk_b%>);
        vk.gamma = Pairing.G2Point(<%vk_gamma%>);
        vk.delta = Pairing.G2Point(<%vk_delta%>);
        vk.gamma_abc = new Pairing.G1Point[](<%vk_gamma_abc_length%>);
        <%vk_gamma_abc_pts%>
    }
    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.a), vk.b)) return 1;
        return 0;
    }
    event Verified(string s);
    function verifyTx(
            Proof memory proof,
            uint[<%vk_input_length%>] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
"#;

const CONTRACT_TEMPLATE: &str = r#"
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.a = Pairing.G1Point(<%vk_a%>);
        vk.b = Pairing.G2Point(<%vk_b%>);
        vk.gamma = Pairing.G2Point(<%vk_gamma%>);
        vk.delta = Pairing.G2Point(<%vk_delta%>);
        vk.gamma_abc = new Pairing.G1Point[](<%vk_gamma_abc_length%>);
        <%vk_gamma_abc_pts%>
    }
    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.a), vk.b)) return 1;
        return 0;
    }
    event Verified(string s);
    function verifyTx(
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[<%vk_input_length%>] memory input
        ) public returns (bool r) {
        Proof memory proof;
        proof.a = Pairing.G1Point(a[0], a[1]);
        proof.b = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.c = Pairing.G1Point(c[0], c[1]);
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
"#;


const CONTRACT_AVM_TEMPLATE: &str = r#"

package org.aion.avm.embed.tetryon;

import avm.Blockchain;
import org.aion.avm.embed.tetryon.bn128.*;
import org.aion.avm.tooling.abi.Callable;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Hello world example (g16). Auto-generated by Zokrates.
 *
 * Circuit accepts two arguments (private: a, public: b); generates proof for statement a^2 == b
 * (i.e. I know some 'a', such that a^2 == b, for some publicly known 'b', without revealing the value for 'a').
 */
@SuppressWarnings("WeakerAccess")
public class Verifier {

    public static final int WORD_SIZE=32;

    protected static class VerifyingKey {
        public final G1Point alpha;
        public final G2Point beta;
        public final G2Point gamma;
        public final G2Point delta;
        public final G1Point[] gamma_abc;

        public VerifyingKey(G1Point alpha, G2Point beta, G2Point gamma, G2Point delta, G1Point[] gamma_abc) {
            this.alpha = alpha;
            this.beta = beta;
            this.gamma = gamma;
            this.delta = delta;
            this.gamma_abc = gamma_abc;
        }
    }

        protected static class Proof {
        public final G1Point a;
        public final G2Point b;
        public final G1Point c;

        public Proof(G1Point a, G2Point b, G1Point c) {
            this.a = a;
            this.b = b;
            this.c = c;
        }

        // serialized as a | b | c
        public byte[] serialize() {
            byte[] s = new byte[WORD_SIZE*8];

            byte[] a = Util.serializeG1(this.a);
            byte[] b = Util.serializeG2(this.b);
            byte[] c = Util.serializeG1(this.c);

            System.arraycopy(a, 0, s, 0, a.length);
            System.arraycopy(b, 0, s, 6*WORD_SIZE - b.length, b.length);
            System.arraycopy(c, 0, s, 8*WORD_SIZE - c.length, c.length);

            return s;
        }

        public static Proof deserialize(byte[] data) {
            assert data.length == 8*WORD_SIZE;

            G1Point a = Util.deserializeG1(Arrays.copyOfRange(data, 0, 2*WORD_SIZE));
            G2Point b = Util.deserializeG2(Arrays.copyOfRange(data, 2*WORD_SIZE, 6*WORD_SIZE));
            G1Point c = Util.deserializeG1(Arrays.copyOfRange(data, 6*WORD_SIZE, 8*WORD_SIZE));

            return new Proof(a, b, c);
        }
    }

        protected static VerifyingKey verifyingKey() {
        G1Point alpha = new G1Point(
                new Fp(new BigInteger("0019120ee247a3e5c0c710de50f86f8be890b9f8ce35591abf182f4d591db8f8", 16)),
                new Fp(new BigInteger("087d9b6ea30dc1fefda2468a53b82005fabfcdd026cee359444642ac16e14e9c", 16))
        );
        G2Point beta = new G2Point(
                new Fp2(new BigInteger("2c76e975c13721befe2860550097061edad5d5e6d4b55d7e0888aa4081bb1b70", 16),
                        new BigInteger("03beea23c38a06edc9577b174c9e046789291db7ef51251e02e053adf41d6ab1", 16)),
                new Fp2(new BigInteger("11820c74e2c88cebeb132852cb0b02fdd23cc77e2927fe70c96bee0342c11c2f", 16),
                        new BigInteger("15383eda06e6734eedcdea2d7564c1827bca49490452bc70374e07d13a3a38ea", 16))
        );
        G2Point gamma = new G2Point(
                new Fp2(new BigInteger("125c637232482e34cf00c0c6393bafe26e310343f4f6383cf6e65ff2a8fab351", 16),
                        new BigInteger("23d45e985239a8c7d0cd091c66fd204d530df129ebbde3cba00950360f60a0bb", 16)),
                new Fp2(new BigInteger("1bce5f9e19392c141016211714944bf88222d77059a7b8939de4d942bfb815b6", 16),
                        new BigInteger("133f401b96c4165c139e22e7dadf859a3a2169485bc9f462042779b76820f444", 16))
        );
        G2Point delta = new G2Point(
                new Fp2(new BigInteger("2d218c6c3c97d36c6a36bdae8aaad026787d5d7bc73fcac935302901cccc8cac", 16),
                        new BigInteger("07dcfa8f6093776cc7003f0a7655178642c624b5158f7767d446e99123569668", 16)),
                new Fp2(new BigInteger("0d34b1da6e22c6fc31ad42e9165598572c98c591e03877bf398d95fc620fc7a9", 16),
                        new BigInteger("1375019c6afcce46743219e2584f57fac17a99f6f105c47d77ccc15f4a12514f", 16))
        );
        G1Point[] gamma_abc = new G1Point[]{
                new G1Point(
                        new Fp(new BigInteger("2da89765d6c25c6d0d63a767bf9d30a7e6b4c040663a8dc1a1a002085d1009c3", 16)),
                        new Fp(new BigInteger("03beb639535322312a2eace06a3ffad50e09fbd12d4762553c166d7e47b20af9", 16))),
                new G1Point(
                        new Fp(new BigInteger("1e870e8b098c7053a851060c1d965b9e177a37c4a6c3bfa9539733ad48704871", 16)),
                        new Fp(new BigInteger("279795f70d42bfe052be9153148c6d16b63bf4564172d45666535882ffd21070", 16))),
                new G1Point(
                        new Fp(new BigInteger("126b7087066e197fd44591d3f9f2df60fa08cc5030f38f5671a13b4bd7d0cd25", 16)),
                        new Fp(new BigInteger("1404cadb49f2910570d68c8163766e71a92676bc3f24c6118574a3ecbd4f0578", 16)))
        };
        return new VerifyingKey(alpha, beta, gamma, delta, gamma_abc);
    }

        public static boolean verify(BigInteger[] input, Proof proof) {

        BigInteger snarkScalarField = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        VerifyingKey vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);

        // X = gamma_0 + gamma_1 * input_0 + gamma_2 * input_1
        G1Point X = new G1Point(Fp.zero(), Fp.zero());
        for (int i = 0; i < input.length; i++) {
            require(input[i].compareTo(snarkScalarField) < 0);
            G1Point tmp = G1.mul(vk.gamma_abc[i + 1], input[i]);
            if (i == 0)
                X = tmp;
            else
                X = G1.add(X, tmp);
        }
        X = G1.add(X, vk.gamma_abc[0]);

        // See [Groth16]
        // [A]_1 * [B]_2 = [alpha]_1 * [beta]_2 + [X]_1 * [gamma]_2 + [C]_1 * [delta]_2
        // e(A, B)
        // e(-X, gamma)
        // e(-C, delta)
        // e(-alpha, beta)
        if (!Pairing.pairingProd4(
                proof.a, proof.b,
                G1.negate(X), vk.gamma,
                G1.negate(proof.c), vk.delta,
                G1.negate(vk.alpha), vk.beta)) return false;

        return true;
    }

    @Callable
    public static boolean verify(BigInteger[] input, byte[] proof) {
        //require(proof.length == 2 + 4 + 2); // a in g1, b in g2, c in g1

        return verify(input, Proof.deserialize(proof));

        /*
        return verify(input, new Proof(
                new G1Point(new Fp(proof[0]), new Fp(proof[1])),
                new G2Point(
                        new Fp2(proof[2], proof[3]),
                        new Fp2(proof[4], proof[5])
                ),
                new G1Point(new Fp(proof[6]), new Fp(proof[7]))
        ));*/
    }

    private static void require(boolean condition) {
        if (!condition) {
            Blockchain.revert();
        }
    }
}

"#;

#[cfg(test)]
mod tests {
    use super::*;
    mod serialize {
        use super::*;

        mod proof {
            use super::*;
            use crate::flat_absy::FlatVariable;
            use crate::ir::*;
            use crate::proof_system::bn128::g16::serialize::serialize_proof;
            use typed_absy::types::{Signature, Type};

            #[allow(dead_code)]
            #[derive(Deserialize)]
            struct G16ProofPoints {
                a: [String; 2],
                b: [[String; 2]; 2],
                c: [String; 2],
            }

            #[allow(dead_code)]
            #[derive(Deserialize)]
            struct G16Proof {
                proof: G16ProofPoints,
                inputs: Vec<String>,
            }

            #[test]
            fn serialize() {
                let program: Prog<FieldPrime> = Prog {
                    main: Function {
                        id: String::from("main"),
                        arguments: vec![FlatVariable::new(0)],
                        returns: vec![FlatVariable::public(0)],
                        statements: vec![Statement::Constraint(
                            FlatVariable::new(0).into(),
                            FlatVariable::public(0).into(),
                        )],
                    },
                    private: vec![false],
                    signature: Signature::new()
                        .inputs(vec![Type::FieldElement])
                        .outputs(vec![Type::FieldElement]),
                };

                let witness = program
                    .clone()
                    .execute(&vec![FieldPrime::from(42)])
                    .unwrap();
                let computation = Computation::with_witness(program, witness);

                let public_inputs_values = computation.public_inputs_values();

                let params = computation.clone().setup();
                let proof = computation.prove(&params);

                let serialized_proof = serialize_proof(&proof, &public_inputs_values);
                serde_json::from_str::<G16Proof>(&serialized_proof).unwrap();
            }
        }
    }
}
