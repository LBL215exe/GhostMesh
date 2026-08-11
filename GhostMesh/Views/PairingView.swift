import SwiftUI
import CoreImage.CIFilterBuiltins
import AVFoundation

struct PairingView: View {
    @EnvironmentObject var vm: AppViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var showScanner = false
    @State private var scannedName = ""
    @State private var pendingBundle: PairingBundle?

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Text("Your code")
                    .font(.headline)
                if let image = qrImage() {
                    Image(uiImage: image)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 220, height: 220)
                }
                Text(vm.identity.fingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)

                Divider().padding(.vertical, 8)

                Button {
                    showScanner = true
                } label: {
                    Label("Scan a contact's code", systemImage: "qrcode.viewfinder")
                }
                .buttonStyle(.borderedProminent)

                Spacer()
            }
            .padding()
            .navigationTitle("Pair a Contact")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .sheet(isPresented: $showScanner) {
                QRScannerView { code in
                    showScanner = false
                    if let bundle = try? PairingBundle.from(base64URL: code) {
                        pendingBundle = bundle
                    }
                }
            }
            .alert("Name this contact", isPresented: .constant(pendingBundle != nil)) {
                TextField("Name", text: $scannedName)
                Button("Add") {
                    if let bundle = pendingBundle {
                        vm.addContact(named: scannedName.isEmpty ? "New Contact" : scannedName, bundle: bundle)
                    }
                    pendingBundle = nil
                    scannedName = ""
                    dismiss()
                }
                Button("Cancel", role: .cancel) {
                    pendingBundle = nil
                    scannedName = ""
                }
            }
        }
    }

    private func qrImage() -> UIImage? {
        guard let payload = try? vm.myPairingBundle().base64URL() else { return nil }
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let context = CIContext()
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

/// Thin AVFoundation QR scanner wrapped for SwiftUI.
struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let vc = ScannerViewController()
        vc.onCode = onCode
        return vc
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}
}

final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    private let session = AVCaptureSession()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else { return }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.frame = view.bounds
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)

        DispatchQueue.global(qos: .userInitiated).async { [session] in session.startRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = object.stringValue else { return }
        session.stopRunning()
        onCode?(value)
    }
}
