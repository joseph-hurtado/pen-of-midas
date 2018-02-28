(defproject com.jamesleonis/pen-of-midas "0.1.0"
  :description "An Ethereum signature verification library"
  :url "http://github.com/jamesleonis/pen-of-midas"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.9.0" :scope "provided"]
                 [org.bouncycastle/bcprov-jdk15on "1.59"]]
  :repl-options {:init-ns pen-of-midas.core})
