(defproject clj-crypto "1.0.1"
  :description "Crypogrphy utilities"
  :dev-dependencies [[swank-clojure "1.4.2"]]
  :local-repo-classpath true
  :plugins [[s3-wagon-private "1.1.1"]]
  :repositories {"releases" "s3p://relay-maven-repo/releases/"
                 "snapshots" "s3p://relay-maven-repo/snapshots/"}
  :dependencies [[org.clojure/clojure "1.2.0"]
                 [org.clojure/clojure-contrib                 "1.2.0"]
                 [swank-clojure/swank-clojure                 "1.4.2"]
                 [org.clojars.kyleburton/clj-etl-utils        "1.0.48"]
                 [commons-lang                                "2.5"]
                 [commons-io/commons-io                       "2.3"]
                 [commons-codec                               "1.6"]])
