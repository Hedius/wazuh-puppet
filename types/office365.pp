# @summary used in wazuh::manager::office365 param as a value. check docs there.
type Wazuh::Office365 = Struct[{
    tenants            => Hash[String, Struct[{
          client_id => String,
          tenant_id => String,
          client_secret => String,
      }]
    ],
    subscriptions      => Optional[Array[String]],
    enabled            => Optional[Enum['yes', 'no']],
    interval           => Optional[String],
    only_future_events => Optional[Enum['yes', 'no']]
  }
]
