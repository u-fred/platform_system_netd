#pragma once

#include <binder/BinderService.h>

#include "android/net/BnNetdExtension.h"

namespace android::net {

class NetdNativeServiceExtension : public BnNetdExtension {
    public:
        static status_t start();
        //static char const* getServiceName() { return "vdc"; }
        binder::Status setVpnDnsCompatModeEnabled(int netId, bool enabled) override;
    };
}  // namespace android::net
