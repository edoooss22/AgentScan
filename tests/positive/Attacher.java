import com.sun.tools.attach.VirtualMachine;
public class Attacher {
    public static void main(String[] a) throws Exception {
        VirtualMachine vm = VirtualMachine.attach(a[0]);
        vm.loadAgent(a[1]);
        vm.detach();
        System.out.println("attached");
    }
}
