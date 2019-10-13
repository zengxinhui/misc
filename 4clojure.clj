(fn _73 [xs]
  (let [xs1 (-> (into xs (apply map vector xs))
                (conj (mapv #(get-in xs %) [[0 0] [1 1] [2 2]]))
                (conj (mapv #(get-in xs %) [[0 2] [1 1] [2 0]])))
        xs1 (->> (map #(apply hash-set %) xs1)
                 (filter #(= 1 (count %)))
                 (apply hash-set))]
    (ffirst (disj xs1 #{:e}))))
