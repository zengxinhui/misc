(fn [xs]
  (->> (-> (into xs (apply map vector xs))
           (conj (mapv #(get-in xs %) [[0 0] [1 1] [2 2]])
                 (mapv #(get-in xs %) [[0 2] [1 1] [2 0]])))
       (map distinct)
       (filter #(= 1 (count %)))
       flatten
       (some #{:x :o})))
