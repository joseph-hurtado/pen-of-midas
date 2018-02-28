(ns pen-of-midas.core
  (:require
    [clojure.string :as s])
  (:import
    org.bouncycastle.asn1.sec.SECNamedCurves
    org.bouncycastle.crypto.digests.KeccakDigest
    org.bouncycastle.crypto.params.ECDomainParameters
    org.bouncycastle.crypto.params.ECPublicKeyParameters
    org.bouncycastle.crypto.signers.ECDSASigner
    org.bouncycastle.math.ec.ECAlgorithms
    org.bouncycastle.math.ec.ECPoint
    org.bouncycastle.util.encoders.Hex))

(defonce
  ^{:private true
    :doc "The SECP256k1 Elliptic Curve used by Bitcoin, Ethereum, and others"}
  ec-curve
  (let [c (SECNamedCurves/getByName "secp256k1")
        params (ECDomainParameters. (.getCurve c) (.getG c) (.getN c) (.getH c))]
    {:params params
     :curve (.getCurve params)
     :N (.getN params)
     :G (.getG params)
     :H (.getH params)}))

(defn- parse-signature
  [signature]
  (let [[r s [v & check]] (partition-all 32 signature)]
    (when (zero? (count check))
      {:r (BigInteger. 1 (byte-array r))
       :s (BigInteger. 1 (byte-array s))
       :v (- v 0x1b)})))

(declare keccak-256)

(defn- H->e
  "4.1.4 - 3.2-4
  Set E = H if (>= (ceiling (log2 n)) (* 8 hashlen)), and set E equal to the
  leftmost (ceiling (log2 n)) bits of H if (< (ceiling (log2 n)) (* 8 hashlen))."
  [H n]
  (let [n-byte-size (/ (.bitLength n) 8)
        E (cond
            (>= n-byte-size (count H)) H
            (< n-byte-size (count H)) (byte-array (take n-byte-size H)))]
    (BigInteger. 1 E)))

(defn- decode-point
  [^bytes r v n]
  (->> r
       ; To decode the point, we need to size the buffer by (count n) bytes of
       ; the lower order bits. Then prepend a compression bit to make the final
       ; count (inc (count n)) bytes.
       reverse
       (take (/ (.bitLength n) 8))
       reverse
       (cons (if (even? v) 0x02 0x03))
       byte-array
       (.decodePoint (:curve ec-curve))))

;; Public

(defn hash-with-prefix
  "Append a prefix to a message and hash."
  [message]
  (let [message-with-prefix
        ; Note that the Ethereum prefix length is (char (count *prefix*))
        ; encoded while the message length is string encoded. This is an
        ; active issue in the Ethereum community.
        ; See: https://github.com/ethereum/go-ethereum/issues/14794
        (str (char 0x19) "Ethereum Signed Message:\n" (count message) message)]
    (keccak-256 (.getBytes message-with-prefix))))

(defn bytes->hex
  "Convert a byte array to a hex-encoded string"
  [^bytes b]
  (str "0x" (Hex/toHexString b)))

(bytes->hex (byte-array [0 1 2 3]))

(defn hex->bytes
  "Convert a hex encoded string into a byte array"
  [^String hex]
  (Hex/decode (if (s/starts-with? hex "0x") (subs hex 2) hex)))

(defn keccak-256
  "The SHA-3 implementation used by Ethereum. Takes a byte array of the data
  and returns a byte-array of the resulting hash."
  [^bytes data]
  (let [engine (doto (KeccakDigest. 256) (.update data 0 (count data)))
        buffer (byte-array (.getDigestSize engine))]
    (.doFinal engine buffer 0)
    buffer))

(defn key->address
  "Takes an encoded ECPoint representing a public key and returns a properly
  formatted hex encoded Ethereum address."
  [^bytes public-key]
  (->> public-key
       (drop 1)
       byte-array
       keccak-256
       (drop 12)
       byte-array
       bytes->hex))

(defn ecrecover
  "Recover the public key used to sign the given message from the signature.
  Returns the byte-array representation of the ECPoint of the public key."
  [^bytes message ^bytes signature]
  (let [{:keys [r s v]} (parse-signature signature)
        n (:N ec-curve)
        ; Ethereum *shouldn't* use 29 and 30 (2 and 3 as v) buuuut...
        x (if (odd? (bit-shift-right v 1)) (.add r n) r)
        R (decode-point (.toByteArray x) v n)]
    (when (.isInfinity (.multiply R n))
      ; Q = r-1 * (sR - eG)
      ; ->
      ; Q = (s)(r-1) * R + (-e)(r-1) * G
      (let [r-1 (.modInverse r n)
            sr-1 (.multiply r-1 s)
            e (H->e message n)
            minuse (.mod (.subtract BigInteger/ZERO e) n)
            minuser-1 (.multiply r-1 minuse)
            Q (ECAlgorithms/sumOfTwoMultiplies R sr-1 (:G ec-curve) minuser-1)]
        (.getEncoded Q false)))))

(defn verify
  "Verify a given message against the provided signature and address
  Returns true if the message was signed by the owner of the public key."
  [^bytes message ^bytes signature ^String address]
  (let [public-key (ecrecover message signature)]
    (if-not (= address (key->address public-key))
      false
      (let [{:keys [r s]} (parse-signature signature)
            key-params (ECPublicKeyParameters.
                         (.decodePoint (:curve ec-curve) public-key)
                         (:params ec-curve))
            authority (doto (ECDSASigner.) (.init false key-params))]
        (try
          (. authority verifySignature message r s)
          (catch NullPointerException _
            (println "Malicious signatures do this. This should not happen")
            false))))))

(comment
  (let [donation-address "0x086d9a9012e9a7ff394817de47b8f3faaef3d97b"
        message (str "If you like this work and would like to support more of "
                     "it, throw some ETH my way. You can verify it's me like this!"
                     donation-address)
        signature
        (str "0xd20cc23c44dad7bd6bf9dd756c9029ec632d98050511784b33353e161cce3d13
              188053664fad3c48d271d3c7f2c52281759edbf3fe62f5c7c65d342c93c9fd391b")]
    (verify (hash-with-prefix message) (hex->bytes signature) donation-address))
  )
