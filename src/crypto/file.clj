(ns crypto.file
  (:import [javax.crypto KeyGenerator SecretKey SecretKeyFactory Cipher CipherOutputStream CipherInputStream]
           [javax.crypto.spec SecretKeySpec PBEKeySpec IvParameterSpec]
           [java.io File FileOutputStream DataInputStream FileInputStream InputStream]
           [org.apache.commons.codec.binary Base64]
           [org.apache.commons.io IOUtils]))

(defn rand-salt [size]
  (let [bytes (byte-array size)]
    (.nextBytes (java.security.SecureRandom.) bytes)
    bytes))

;; Defaults
(def pbe-iteration-count   65536)
(def pbe-key-length        256)
(def cipher-algorithm      "AES/CBC/PKCS5Padding")
(def key-factory-algorithm "PBKDF2WithHmacSHA1")
(def key-encoding          "AES")

(defprotocol B64Encodable
  (encode-b64 [thing]))

(defprotocol B64Decodable
  (decode-b64 [thing]))

(defprotocol SecretKeyable
  (secret-key [thing]))


(extend-type
 (Class/forName "[B")

 B64Encodable
 (encode-b64 [x] (Base64/encodeBase64String ^bytes x))

 B64Decodable
 (decode-b64 [x] x)

 SecretKeyable
 (secret-key [x] (SecretKeySpec. ^bytes x key-encoding)))

(extend-type
 String

 B64Encodable
 (encode-b64 [x] (encode-b64 (.getBytes x)))

 B64Decodable
 (decode-b64 [x] (Base64/decodeBase64 ^bytes (.getBytes x)))

 SecretKeyable
 (secret-key [x] (SecretKeySpec. (decode-b64 x) key-encoding)))

(extend-type
 java.security.Key

 B64Encodable
 (encode-b64 [x] (encode-b64 (.getEncoded x)))

 SecretKeyable
 (secret-key [x] x))

(defn make-secret-key [^String password]
  (let [key-factory  (SecretKeyFactory/getInstance key-factory-algorithm)
        key-spec     (PBEKeySpec. (.toCharArray password)
                                  (rand-salt 20)
                                  pbe-iteration-count
                                  pbe-key-length)]
    (secret-key (.getEncoded (.generateSecret key-factory key-spec)))))


;; NB : I think this may be the same as (.getIV cipher)
;;  - should verify they always return the same thing
(defn get-init-vec-from-cipher [^Cipher cipher]
  (.getIV cipher))

(defn make-cipher
  ([^Integer mode ^SecretKey skey]
     (doto (Cipher/getInstance cipher-algorithm)
       (.init mode (secret-key skey))))
  ([^Integer mode ^SecretKey skey ^IvParameterSpec init-vec]
     (doto (Cipher/getInstance cipher-algorithm)
       (.init mode (secret-key skey) init-vec))))

(defn make-encryption-info [^String password]
  (let [secret-key   (make-secret-key password)
        cipher       (make-cipher Cipher/ENCRYPT_MODE secret-key)
        init-vec     (get-init-vec-from-cipher cipher)]
    {:skey (encode-b64 secret-key)
     :ivec (encode-b64 init-vec)}))

(defn make-encryption-info-from-secret-key [skey]
  (let [secret-key   (secret-key skey)
        cipher       (make-cipher Cipher/ENCRYPT_MODE secret-key)
        init-vec     (get-init-vec-from-cipher cipher)]
    {:skey (encode-b64 secret-key)
     :ivec (encode-b64 init-vec)}))

;; Adapted from: http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
(defn file-encrypt [^String infile ^String outfile ^String password]
  (let [secret-key   (make-secret-key password)
        cipher       (make-cipher Cipher/ENCRYPT_MODE secret-key)
        init-vec     (get-init-vec-from-cipher cipher)]
    (with-open [istream (java.io.FileInputStream. infile)
                ostream (CipherOutputStream. (java.io.FileOutputStream. outfile) cipher)]
      (IOUtils/copy istream ostream))
    {:skey (encode-b64 secret-key)
     :ivec (encode-b64 init-vec)}))


;; Adapted from: http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
(defn file-decrypt [^String infile ^String outfile secret-key init-vec]
  (let [skey   (decode-b64 secret-key)
        ivec   (decode-b64 init-vec)
        cipher (make-cipher Cipher/DECRYPT_MODE (SecretKeySpec. skey key-encoding) (IvParameterSpec. ivec))]
    (with-open [istream (CipherInputStream. (FileInputStream. infile) cipher)
                ostream (java.io.FileOutputStream. outfile)]
      (IOUtils/copy istream ostream))))

(defn get-encryption-stream
  ([^String infilename password]
     (let [secret-key   (make-secret-key password)
           cipher       (make-cipher Cipher/ENCRYPT_MODE secret-key)
           init-vec     (get-init-vec-from-cipher cipher)
           stream       (CipherInputStream. (FileInputStream. infilename) cipher)]
       {:skey   (encode-b64 secret-key)
        :ivec   (encode-b64 init-vec)
        :stream stream}))
  ([^String infilename skey ivec]
     (let [cipher (make-cipher Cipher/ENCRYPT_MODE (secret-key (decode-b64 skey)) (IvParameterSpec. (decode-b64 ivec)))
           stream (CipherInputStream. (FileInputStream. infilename) cipher)]
       {:skey   skey
        :ivec   ivec
        :stream stream})))

(defn encrypt-stream
  ([^InputStream istream ^String password]
     (let [secret-key   (make-secret-key password)
           cipher       (make-cipher Cipher/ENCRYPT_MODE secret-key)
           init-vec     (get-init-vec-from-cipher cipher)
           stream       (CipherInputStream. istream cipher)]
       {:skey   (encode-b64 secret-key)
        :ivec   (encode-b64 init-vec)
        :stream stream}))
  ([^InputStream istream sec-key init-vec]
     (let [skey   (secret-key sec-key)
           ivec   (decode-b64 init-vec)
           param-spec (IvParameterSpec. ivec)
           cipher (make-cipher Cipher/ENCRYPT_MODE skey param-spec)
           stream (CipherInputStream. istream cipher)]
       {:skey   sec-key
        :ivec   init-vec
        :stream stream})))

(defn get-decryption-stream [^InputStream instream skey ivec]
  (let [cipher (make-cipher
                Cipher/DECRYPT_MODE
                (secret-key (decode-b64 skey))
                (IvParameterSpec. (decode-b64 ivec)))]
    (CipherInputStream. instream cipher)))
