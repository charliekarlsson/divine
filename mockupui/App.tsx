import { useState } from 'react';
import { PhoneLogin } from './components/PhoneLogin';
import { WalletSetup } from './components/WalletSetup';
import { WalletHome } from './components/WalletHome';
import { SendCrypto } from './components/SendCrypto';
import { WalletAddressModal } from './components/WalletAddressModal';

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [hasWallet, setHasWallet] = useState(false);
  const [showSendCrypto, setShowSendCrypto] = useState(false);
  const [showAddressModal, setShowAddressModal] = useState(false);

  const handleLogin = (isNewUser: boolean) => {
    setIsLoggedIn(true);
    setHasWallet(!isNewUser); // If new user, they don't have a wallet yet
  };

  const handleWalletSetupComplete = () => {
    setHasWallet(true);
  };

  if (!isLoggedIn) {
    return <PhoneLogin onLogin={handleLogin} />;
  }

  if (!hasWallet) {
    return <WalletSetup onComplete={handleWalletSetupComplete} />;
  }

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
      <div className="w-[360px] h-[600px] bg-white rounded-lg shadow-2xl overflow-hidden relative">
        <WalletHome 
          onSendClick={() => setShowSendCrypto(true)} 
          onProfileClick={() => setShowAddressModal(true)}
        />
        {showSendCrypto && <SendCrypto onClose={() => setShowSendCrypto(false)} />}
        {showAddressModal && <WalletAddressModal onClose={() => setShowAddressModal(false)} />}
      </div>
    </div>
  );
}