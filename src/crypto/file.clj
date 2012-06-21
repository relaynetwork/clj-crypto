(ns crypto.file
  (:import [javax.crypto KeyGenerator SecretKey SecretKeyFactory Cipher CipherOutputStream CipherInputStream]
           [javax.crypto.spec SecretKeySpec PBEKeySpec IvParameterSpec]
           [java.io File FileOutputStream DataInputStream FileInputStream InputStream]
           [org.apache.commons.codec.binary Base64]
           [org.apache.commons.io IOUtils])
  (:use
   [clj-etl-utils.lang-utils :only [raise aprog1]]))

(defn rand-salt [size]
  (aprog1
      (byte-array size)
    (.nextBytes (java.security.SecureRandom.) it)))

;; Defaults
(def *pbe-iteration-count*   65536)
(def *pbe-key-length*        256)
(def *cipher-algorithm*      "AES/CBC/PKCS5Padding")
(def *key-factory-algorithm* "PBKDF2WithHmacSHA1")
(def *key-encoding*          "AES")

(defn make-secret-key [password]
  (let [key-factory  (SecretKeyFactory/getInstance *key-factory-algorithm*)
        key-spec     (PBEKeySpec. (.toCharArray password)
                                  (rand-salt 20)
                                  *pbe-iteration-count*
                                  *pbe-key-length*)]
    (SecretKeySpec. (.getEncoded (.generateSecret key-factory key-spec)) *key-encoding*)))

(defn get-init-vec-from-cipher [cipher]
  (-> cipher
      (.getParameters)
      (.getParameterSpec IvParameterSpec)
      (.getIV)))

(defn make-cipher
  ([mode secret-key]
     (doto (Cipher/getInstance *cipher-algorithm*)
       (.init mode secret-key)))
  ([mode secret-key init-vec]
     (doto (Cipher/getInstance *cipher-algorithm*)
       (.init mode secret-key init-vec))))

(defn make-encryption-info [password]
  (let [secret-key   (make-secret-key password)
        cipher       (make-cipher Cipher/ENCRYPT_MODE secret-key)
        init-vec     (get-init-vec-from-cipher cipher)]
    {:skey (Base64/encodeBase64String (.getEncoded secret-key))
     :ivec (Base64/encodeBase64String init-vec)}))

;; Adapted from: http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
(defn file-encrypt [infile outfile password]
  (let [secret-key   (make-secret-key password)
        cipher       (make-cipher Cipher/ENCRYPT_MODE secret-key)
        init-vec     (get-init-vec-from-cipher cipher)]
    (with-open [istream (java.io.FileInputStream. infile)
                ostream (CipherOutputStream. (java.io.FileOutputStream. outfile) cipher)]
      (IOUtils/copy istream ostream))
    {:skey (Base64/encodeBase64String (.getEncoded secret-key))
     :ivec (Base64/encodeBase64String init-vec)}))


;; Adapted from: http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
(defn file-decrypt [infile outfile secret-key init-vec]
  (let [skey   (if (Base64/isBase64 secret-key)
                 (Base64/decodeBase64 secret-key)
                 secret-key)
        ivec   (if (Base64/isBase64 init-vec)
                 (Base64/decodeBase64 init-vec)
                 init-vec)
        cipher (make-cipher Cipher/DECRYPT_MODE (SecretKeySpec. skey *key-encoding*) (IvParameterSpec. ivec))]
    (with-open [istream (CipherInputStream. (FileInputStream. infile) cipher)
                ostream (java.io.FileOutputStream. outfile)]
      (IOUtils/copy istream ostream))))

(defn get-encryption-stream
  ([infilename password]
     (let [secret-key   (make-secret-key password)
           cipher       (make-cipher Cipher/ENCRYPT_MODE secret-key)
           init-vec     (get-init-vec-from-cipher cipher)
           stream       (CipherInputStream. (FileInputStream. infilename) cipher)]
       {:skey   (Base64/encodeBase64String (.getEncoded secret-key))
        :ivec   (Base64/encodeBase64String init-vec)
        :stream stream}))
  ([infilename secret-key init-vec]
     (let [skey   (if (Base64/isBase64 secret-key)
                    (Base64/decodeBase64 secret-key)
                    secret-key)
           ivec   (if (Base64/isBase64 init-vec)
                    (Base64/decodeBase64 init-vec)
                    init-vec)
           cipher (make-cipher Cipher/ENCRYPT_MODE (SecretKeySpec. skey *key-encoding*) (IvParameterSpec. ivec))
           stream (CipherInputStream. (FileInputStream. infilename) cipher)]
       {:skey   (Base64/encodeBase64String skey)
        :ivec   (Base64/encodeBase64String ivec)
        :stream stream})))


(defn encrypt-stream
  ([istream password]
     (let [secret-key   (make-secret-key password)
           cipher       (make-cipher Cipher/ENCRYPT_MODE secret-key)
           init-vec     (get-init-vec-from-cipher cipher)
           stream       (CipherInputStream. istream cipher)]
       {:skey   (Base64/encodeBase64String (.getEncoded secret-key))
        :ivec   (Base64/encodeBase64String init-vec)
        :stream stream})))

(defn get-decryption-stream [#^InputStream instream secret-key init-vec]
  (let [skey   (if (Base64/isBase64 secret-key)
                 (Base64/decodeBase64 secret-key)
                 secret-key)
        ivec   (if (Base64/isBase64 init-vec)
                 (Base64/decodeBase64 init-vec)
                 init-vec)
        cipher (make-cipher Cipher/DECRYPT_MODE (SecretKeySpec. skey *key-encoding*) (IvParameterSpec. ivec))]
    (CipherInputStream. instream cipher)))
