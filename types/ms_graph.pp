# @summary used in wazuh::manager::ms_graph param as a value. check docs there.
type Wazuh::MS_Graph = Struct[{
    tenants            => Hash[String, Struct[{
          client_id => String,
          tenant_id => String,
          secret_value => String,
      }]
    ],
    resources          => Optional[Hash[String, Array[String]]],
    enabled            => Optional[Enum['yes', 'no']],
    interval           => Optional[String],
    only_future_events => Optional[Enum['yes', 'no']]
  }
]
