public class Target {
    static int counter;
    static int tick() { return ++counter; }
    public static void main(String[] a) throws Exception {
        System.out.println("target pid " + ProcessHandle.current().pid());
        while (true) { tick(); Thread.sleep(50); }
    }
}
