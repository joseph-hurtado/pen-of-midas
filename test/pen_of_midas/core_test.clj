(ns pen-of-midas.core-test
  (:require [clojure.test :refer :all]
            [pen-of-midas.core :refer :all]))

(deftest sha3-hash
  (doseq [[input check]
          [["test123" "0xf81b517a242b218999ec8eec0ea6e2ddbef2a367a14e93f4a32a39e260f686ad"]
           ["abc" "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"]
           ["test(int)" "0xf4d03772bec1e62fbe8c5691e1a9101e520e8f8b5ca612123694632bf3cb51b1"]
           ["0x80" "0x6b03a5eef7706e3fb52a61c19ab1122fad7237726601ac665bd4def888f0e4a0"]
           ["hello" "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"]
           ["aaa" "0xb9a5dc0048db9a7d13548781df3cd4b2334606391f75f40c14225a92f4cb3537"]]]
    (testing (str "keccak(" input "): " check)
      (is (= check (bytes->hex (keccak-256 (.getBytes input))))))))

(deftest recover-key-from-signature
  (let [public-key
        (hex->bytes (str "0x506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aab"
                         "a645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76"))
        account "0xef678007d18427e6022059dbc264f27507cd1ffc"
        message (keccak-256 (.getBytes "A test message"))
        signature
        (let [r "9631f6d21dec448a213585a4a41a28ef3d4337548aa34734478b563036163786"
              s "2ff816ee6bbb82719e983ecd8a33a4b45d32a4b58377ef1381163d75eedc900b"]
          (hex->bytes (str r s "1b")))
        recovered-key (ecrecover message signature)]
    (testing "Recovered key matches public key"
      (is (= (BigInteger. 1 public-key)
             (->> recovered-key
                  (drop 1)
                  byte-array
                  (BigInteger. 1)))))
    (testing "Recovered key matches address key"
      (is (= account
             (key->address (byte-array (cons 0xFF public-key)))
             (key->address recovered-key))))
    (testing "Verify signature matches message"
      (is (verify message signature account)))
    (testing "Fail bad signatures"
      (is (not (verify (keccak-256 (.getBytes "abc")) signature account))))))

(deftest verify-go-ethereum-generated-signatures
  (doseq [{:keys [account message signature] :as test-case}
          [{:account "0x5ec3bb0e12a32e7f9fc426e750f33372813cfa43"
            :message "deadbeaf"
            :signature
            (hex->bytes (str "0xab8f376d8c8fd45790fcc5a6c5b8319251109811794fc2e69e6b5026b8a7fcac"
                             "368f8946eb160ce4ef1b0a9f765f0040c9d9add7ebc50a48b5855c439fa7683d1b"))}
           {:account "0x5ec3bb0e12a32e7f9fc426e750f33372813cfa43"
            :message "hello-world"
            :signature
            (hex->bytes (str "0x90f33e2d2eb33a3c72078260af0e835bf3634f7286177a72050b20eafc58c4c3"
                             "5eecbcfbdebd050eb6698954250f5d6d25b1b0bfc8ff72aa0bc4612c7437b9831b"))}]]
    (testing (str "Verify " message " is from " account)
      (is (verify (hash-with-prefix message) signature account))
      (is (= account (key->address (ecrecover (hash-with-prefix message) signature)))))))
