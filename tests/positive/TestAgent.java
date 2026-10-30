import java.lang.instrument.*;
import java.security.ProtectionDomain;
public class TestAgent {
    static class Spy implements ClassFileTransformer {
        public byte[] transform(ClassLoader l, String name, Class<?> c, ProtectionDomain d, byte[] b) {
            return null;
        }
    }
    static void go(Instrumentation inst) throws Exception {
        Spy s = new Spy();
        inst.addTransformer(s, true);
        for (Class<?> c : inst.getAllLoadedClasses())
            if (c.getName().equals("Target")) inst.retransformClasses(c);
        System.out.println("agent: transformer installed, Target retransformed");
    }
    public static void premain(String args, Instrumentation inst) throws Exception { go(inst); }
    public static void agentmain(String args, Instrumentation inst) throws Exception { go(inst); }
}
