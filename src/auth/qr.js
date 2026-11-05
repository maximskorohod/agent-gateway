// QR-код для подключения приложения-аутентификатора
import QRCode from 'qrcode';
export async function qrSvg(text) {
  return QRCode.toString(text, { type: 'svg', margin: 1, width: 220, errorCorrectionLevel: 'M' });
}
