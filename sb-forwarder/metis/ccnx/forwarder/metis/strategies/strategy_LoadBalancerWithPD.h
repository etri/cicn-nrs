/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



/**
 * Forward on the less loaded path taking into account the propagation delay of the first hop
 */

#ifndef Metis_strategy_LoadBalancerWithPD_h
#define Metis_strategy_LoadBalancerWithPD_h

#include <ccnx/forwarder/metis/strategies/metis_Strategy.h>
#include <ccnx/forwarder/metis/core/metis_ConnectionTable.h>

MetisStrategyImpl *strategyLoadBalancerWithPD_Create();
void strategyLoadBalancerWithPD_SetConnectionTable(MetisStrategyImpl *strategy, MetisConnectionTable *connTable);
#endif // Metis_strategy_LoadBalancerWithPD_h
