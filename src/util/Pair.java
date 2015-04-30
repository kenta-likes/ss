package util;

public class Pair<K, V> {
    private K k;
    private V v;

    public Pair(K fst, V snd) {
        k = fst;
        v = snd;
    }

    public K first() {
        return k;
    }

    public V second() {
        return v;
    }
    
    public void setFirst(K knew) {
    	k = knew;
    }
    
    public void setSecond(V vnew) {
    	v = vnew; 
    }
}

