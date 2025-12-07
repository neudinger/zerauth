// This function is the exported module name from the CMAKE_TOOLCHAIN_FILE
Zerauth().then((Zerauth) => {
    // Access the exported C++ function via the Module object

    const salt = Zerauth.generate_random_string(10);
    console.log(`salt is ${salt}`);

    const random_selected_curve = Zerauth.random_curves_selections(2);

    const manual_selected_curve = new Zerauth.StringList();
    manual_selected_curve.push_back("secp521r1");
    manual_selected_curve.push_back("prime256v1");
    manual_selected_curve.push_back("sect571r1");
    manual_selected_curve.push_back("c2tnb431r1");
    manual_selected_curve.push_back("wap-wsg-idm-ecid-wtls12");
    manual_selected_curve.push_back("brainpoolP512t1");


    for (let i = 0; i < random_selected_curve.size(); i++) {
        // Use .get(i) to retrieve the string at index i
        const str = random_selected_curve.get(i);
        console.log(`Item at index ${i}: ${str}`);
    }

    const commitment_setup_b64_expected = Zerauth.create_commitment_setup("password", manual_selected_curve, salt);
    random_selected_curve.delete();
    manual_selected_curve.delete();

    if (commitment_setup_b64_expected.isSuccess) {
        // Success case: Access the value member
        console.log("✅ Success! Value:", commitment_setup_b64_expected.value);
    } else {
        // Error case: Access the error member
        console.error("❌ Failed! Error:", commitment_setup_b64_expected.error);
    }

    const challenge_b64_expected = Zerauth.create_challenge(commitment_setup_b64_expected.value);

    if (commitment_setup_b64_expected.isSuccess) {
        // Success case: Access the value member
        console.log("✅ Success! Value:", challenge_b64_expected.value);
    } else {
        // Error case: Access the error member
        console.error("❌ Failed! Error:", challenge_b64_expected.error);
    }

    const proving_form_b64 = challenge_b64_expected.value.first;
    const transient_parameter_b64 = challenge_b64_expected.value.second;

    console.log("proving_form_b64 = ", proving_form_b64);
    console.log("transient_parameter_b64 = ", transient_parameter_b64);

    const proof_hex_expected = Zerauth.solve_challenge("password", proving_form_b64)

    if (proof_hex_expected.isSuccess) {
        // Success case: Access the value member
        console.log("✅ Success! Value:", proof_hex_expected.value);
    } else {
        // Error case: Access the error member
        console.error("❌ Failed! Error:", proof_hex_expected.error);
    }



    const verification = Zerauth.verify(proof_hex_expected.value, transient_parameter_b64)

    if (verification.isSuccess) {
        // Success case: Access the value member
        console.log("✅ Success! Value:", verification.value);
    } else {
        // Error case: Access the error member
        console.error("❌ Failed! Error:", verification.error);
    }

    if (verification.value == true) {
        console.log("The proof is valid");
    }

}).catch((error) => {
    console.error("Error loading WASM module:", error);
});
