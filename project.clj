(defproject com.relaynetwork/clj-crypto "1.0.13"
  :description "Crypogrphy utilities"
  :local-repo-classpath true
  :global-vars {*warn-on-reflection* true}
  :plugins [[s3-wagon-private          "1.1.2"]
            [lein-release/lein-release "1.0.5"]
            [lein-swank                "1.4.5"]]
  :lein-release {:deploy-via :clojars}
  :repositories [["releases" {:url "s3p://relay-maven-repo/releases/" :creds :gpg}]
                 ["snapshots" {:url "s3p://relay-maven-repo/snapshots/" :creds :gpg}]]
  :profiles             {:dev {:dependencies [[swank-clojure "1.4.3"]]}
                         :1.2 {:dependencies [[org.clojure/clojure "1.2.0"]
                                              [org.clojure/data.json      "0.2.2"]]}
                         :1.3 {:dependencies [[org.clojure/clojure "1.3.0"]
                                              [org.clojure/data.json      "0.2.3"]]}
                         :1.4 {:dependencies [[org.clojure/clojure "1.4.0"]
                                              [org.clojure/data.json      "0.2.3"]]}
                         :1.5 {:dependencies [[org.clojure/clojure "1.5.1"]
                                              [org.clojure/data.json      "0.2.3"]]}
                         :1.6 {:dependencies [[org.clojure/clojure "1.6.0-master-SNAPSHOT"]
                                              [org.clojure/data.json      "0.2.3"]]}}
  :aliases              {"all" ["with-profile" "dev,1.2:dev,1.3:dev,1.4:dev,1.5:dev,1.6"]}
  :dependencies [[commons-lang                                "2.5"]
                 [commons-io/commons-io                       "2.4"]
                 [commons-codec                               "1.7"]])
