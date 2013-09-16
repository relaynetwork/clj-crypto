(ns crypto.file-test
  (:require
   [crypto.file  :as crypt])
  (:use
   clojure.test)
  (:import
   [java.io ByteArrayInputStream ByteArrayOutputStream]
   [org.apache.commons.io IOUtils]))


(deftest round-robin-encrypt-stream-password
  (let [message               "this is a very secret message"
        password              "supersecretpassword123"
        input-byte-stream     (ByteArrayInputStream. (.getBytes message))
        encrypted-byte-stream (ByteArrayOutputStream.)
        data                  (crypt/encrypt-stream input-byte-stream password)
        decrypted-byte-stream (ByteArrayOutputStream.)]
    ;; First encrypt the data, stream encrypted bytes to output byte array
    (IOUtils/copy (:stream data) encrypted-byte-stream)

    ;; Then decrypt those bytes and assert that the message is correct
    (IOUtils/copy (crypt/get-decryption-stream
                   (ByteArrayInputStream. (.toByteArray encrypted-byte-stream))
                   (:skey data)
                   (:ivec data))
                  decrypted-byte-stream)

    (is (= message (.toString decrypted-byte-stream "UTF-8")))))
