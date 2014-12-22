#!/usr/bin/env python
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from datetime import datetime, timedelta
import json
import os
import sys
import argparse

import dateutil
from xml.sax.saxutils import escape

from stix.campaign import (Campaign, Names)
from stix.coa import (CourseOfAction)
from stix.common import (Statement, Confidence, InformationSource, RelatedThreatActor, DateTimeWithPrecision, Identity)
from stix.common.related import (RelatedTTP, RelatedExploitTarget)
from stix.common.vocabs import (VocabString, Motivation, ThreatActorType, MalwareType, LossProperty, AvailabilityLossType,
                                DiscoveryMethod, HighMediumLow, AssetType, ManagementClass, OwnershipClass, SecurityCompromise,
                                ImpactRating, LossDuration, LocationClass)
from stix.core import STIXPackage, STIXHeader
from stix.exploit_target import (ExploitTarget, Vulnerability)
from stix.extensions.identity.ciq_identity_3_0 import (CIQIdentity3_0Instance, STIXCIQIdentity3_0, Country,
                                                       Address, OrganisationInfo, PartyName, AdministrativeArea)

from stix.incident import (Incident, AffectedAsset, PropertyAffected, Time, LeveragedTTPs, ExternalID, AttributedThreatActors)
from stix.incident.impact_assessment import (ImpactAssessment, TotalLossEstimation, ImpactQualification)
from stix.incident.direct_impact_summary import DirectImpactSummary
from stix.incident.loss_estimation import LossEstimation
from stix.threat_actor import (ThreatActor, ObservedTTPs)
from stix.ttp import (TTP, Behavior, VictimTargeting, ExploitTargets)
from stix.ttp.attack_pattern import (AttackPattern)
from stix.ttp.malware_instance import (MalwareInstance)
from stix.ttp.exploit import (Exploit)
from cybox.common.tools import (ToolInformation, ToolInformationList)
import utilities

EXIT_ERROR = 1

__version__ = 0.1

def info(fmt, *args):
    msg = fmt % args
    print "[INFO]", msg

def warn(fmt, *args):
    msg = fmt % args
    sys.stderr.write("[WARN] %s\n" % msg)

def error(fmt, *args):
    msg = fmt % args
    sys.stderr.write("[ERROR] %s\n" % msg)

def map_malware_variety_item_to_malware_type(item):
    if item == "Adware":
        return MalwareType.TERM_ADWARE
    elif item == "Backdoor":
        return MalwareType.TERM_REMOTE_ACCESS_TROJAN
    elif item == "Ransomware":
        return MalwareType.TERM_RANSOMWARE
    elif item == "Rootkit":
        return MalwareType.TERM_ROOTKIT
    elif item == "Spam":
        return MalwareType.TERM_BOT_SPAM
    else:
        return VocabString(item)

def remember_cves(cve_item, ttp):
    global cve_info
    if cve_item:
        cves = []
        for cve in cve_item.split(','):
            cves.append(cve.strip())
        cve_info.append({"cves": cves, "related_ttp": ttp})
        
def add_malware(malware_item, ttp):
    ttp.behavior = Behavior()
    malware_instance = MalwareInstance()
    for item in malware_item.get('variety'):
        malware_instance.add_type(map_malware_variety_item_to_malware_type(item))
    malware_instance.add_name(malware_item.get('name'))
    notes_item = malware_item.get('notes')
    if notes_item:
        malware_instance.description = escape(notes_item)
    remember_cves(malware_item.get('cve'), ttp)
    ttp.behavior.add_malware_instance(malware_instance)
    
def map_socal_item_to_capecid(item):
    if item == "Phishing":
        return "CAPEC-98"
    else:
        warn("'social/variety' item %s not handled yet", item)
        return None
    
def add_social(social_item, ttp):
    global targets_item
    targets_item = social_item.get('target')
    if not targets_item:
        error("Required 'target' item is missing in 'action/socal' item")
    # TODO: target
    notes_item = social_item.get('notes')
    if notes_item:
        ttp.description = "Notes: " + escape(notes_item)
    variety_item = social_item.get("variety")
    if not variety_item:
        error("Required 'variety' item is missing in 'action/socal' item")
    else:
        # the only one that makes sense to create an attack pattern for is "Phishing", what if isn't the first?
        capec_id = map_socal_item_to_capecid(variety_item[0])
        if capec_id:
            ttp.behavior = Behavior()
            attack_pattern = AttackPattern()
            attack_pattern.capec_id = capec_id
            ttp.behavior.add_attack_pattern(attack_pattern)
        # what to do with varieties other than Phishing?
        
def add_misuse_item(misuse_item, ttp):
    pass
    
def add_hacking(hacking_item, ttp):
    remember_cves(hacking_item.get('cve'), ttp)
    ttp.behavior = Behavior()
    variety_item = hacking_item.get("variety")
    vector_item = hacking_item.get("vector") 
    # notes?
    for item in variety_item:
        attack_pattern = AttackPattern()
        capec_info = utilities.ATTACK_PATTERN_MAPPING.get(item)
        if not capec_info:
            error("'%s' in 'action/hacking' item not found in attack_pattern mapping", item)
        elif capec_info == 0:
            warn("'%s' in 'action/hacking' item has no mapping, yet", item)
        elif capec_info == "Other":
            attack_pattern.title = "Other"
            ttp.behavior.add_attack_pattern(attack_pattern)
        elif capec_info == "Unknown":
            attack_pattern.title = "Unknown"
            ttp.behavior.add_attack_pattern(attack_pattern)
        else:    
            attack_pattern.capec_id = capec_info[0]
            attack_pattern.title = capec_info[1]
            ttp.behavior.add_attack_pattern(attack_pattern)
    
def add_physical(physical_item, pkg):
    global location_info
    location_items = physical_item.get('location')
    if not location_items:
        error("The 'physical/location' item is required")
    else:
        # https://github.com/STIXProject/python-stix/issues/134
        warn("The 'physical/location' item is not handled, yet")
   
def add_action_item(action_item, pkg):
    if action_item.get('environmental'):
        warn("'environmental' item in 'action' item does not map to any STIX concept")
    error_item = action_item.get('error')
    if  error_item:
        warn("'error' item in 'action' item not handled, yet")
    hacking_item = action_item.get('hacking')
    if  hacking_item:
        hacking_ttp = TTP()
        add_hacking(hacking_item, hacking_ttp)
        pkg.add_ttp(hacking_ttp)
    malware_item = action_item.get('malware')
    if malware_item:
        malware_ttp = TTP()
        add_malware(malware_item, malware_ttp)
        pkg.add_ttp(malware_ttp)
    misuse_item = action_item.get('misuse')
    if misuse_item:
        warn("'misuse' item in 'action' item not handled, yet")
        #warn("'misuse' item in 'action' item maps to TTP")
        #misusattack_patternTP = TTP()
        #add_misuse_item(misuse_item, misuseTTP)
        #pkg.add_ttp(misuseTTP)
    physical_item = action_item.get('physical')
    if physical_item:
        add_physical(physical_item, pkg)
    social_item = action_item.get('social') 
    if social_item:
        social_ttp = TTP()
        add_social(social_item, social_ttp)
        pkg.add_ttp(social_ttp)
    unknown_item = action_item.get('unknown')
    if  unknown_item:
        unknown_ttp = TTP()
        unknown_ttp.title = "Unknown"
        notes_item = unknown_item.get("notes")
        if notes_item:
            unknown_ttp.title += " - " + escape(notes_item)
        pkg.add_ttp(unknown_ttp)
    
def map_motive_item_to_motivation(item):
    if item == "Fun":
        return Motivation(Motivation.TERM_EGO)
    elif item == "Financial":
        return Motivation(Motivation.TERM_FINANCIAL_OR_ECONOMIC)
    elif item == "Ideology":
        return Motivation(Motivation.TERM_IDEOLOGICAL)
    elif item == "Convenience":
        return Motivation(Motivation.TERM_OPPORTUNISTIC)
    else:
        warn("'%s' in 'motive' item not mapped - not using controlled vocab, use as is", item)
        return VocabString(item)
    
def map_actor_variety_item_to_threat_actor_type(item):
    if item == "Activist":
        return ThreatActorType(ThreatActorType.TERM_HACKTIVIST)
    elif item == "Customer":
        return ThreatActorType(ThreatActorType.TERM_DISGRUNTLED_CUSTOMER_OR_USER)
    elif item == "Organized crime":
        return ThreatActorType(ThreatActorType.TERM_ECRIME_ACTOR_ORGANIZED_CRIME_ACTOR)
    elif item == "State-affiliated":
        return ThreatActorType(ThreatActorType.TERM_STATE_ACTOR_OR_AGENCY)
    else:
        warn("'%s' in 'actor/external/variety' item not mapped - not using controlled vocab, use as is", item)
        return VocabString(item)

def add_external_or_partner_actor_ttem(item, pkg):
    ta = ThreatActor()
    ta.identity = CIQIdentity3_0Instance()
    identity_spec = STIXCIQIdentity3_0()
    country_item = item.get('country')
    if not country_item:
        error("Required 'country' item is missing in 'actor/external' or 'actor/partner' item")
    else:  
        for c in country_item:
            address = Address()
            address.country = Country()
            address.country.add_name_element(c)
            identity_spec.add_address(address)
        ta.identity.specification = identity_spec
    motive_item = item.get('motive')
    if not motive_item:
        error("Required 'motive' item is missing in 'actor/external' or 'actor/partner' item")
    else:
        for m in motive_item:
            motivation = Statement()
            motivation.value = map_motive_item_to_motivation(m)
            ta.add_motivation(motivation)
    variety_item = item.get('variety')        
    if not variety_item:
        error("Required 'variety' item is missing in 'actor/external' or 'actor/partner' item")
    else:
        for v in variety_item:
            ta_type = Statement()
            ta_type.value = map_actor_variety_item_to_threat_actor_type(v)
            ta.add_type(ta_type)
    notes_item = item.get('notes')
    if notes_item:
        ta.description = "Notes: " + escape(notes_item)
    pkg.add_threat_actor(ta)
            
def add_internal_actor_item(internal_item, pkg):
    ta = ThreatActor()
    motive_item = internal_item.get('motive')
    if not motive_item:
        error("Required 'motive' item is missing in 'actor/internal' item")
    else:
        for item in motive_item:
            motivation = Statement()
            motivation.value = map_motive_item_to_motivation(item)
    ta.add_motivation(motivation)
    # job_change added in 1.3
    variety_item = internal_item.get('variety')        
    if not variety_item:
        error("Required 'variety' item is missing in 'actor/internal' item")
    else:
        for v in variety_item:
            ta_type = Statement()
            ta_type.value = ThreatActorType(ThreatActorType.TERM_INSIDER_THREAT)
            ta_type.description = v
            ta.add_type(ta_type)
    notes_item = internal_item.get('notes')
    if notes_item:
        ta.description = "Notes: " + escape(notes_item)
    pkg.add_threat_actor(ta)
        
# if there is more than one actor, are they all related?
def add_actor_item(actor_item, pkg):
    ta = ThreatActor()
    external_item = actor_item.get('external')
    if external_item:
        add_external_or_partner_actor_ttem(external_item, pkg)
    internal_item = actor_item.get('internal')
    if internal_item:
        add_internal_actor_item(internal_item, pkg)
    # this is a partner of the victim...  
    partner_item = actor_item.get('partner')
    if partner_item:
        add_external_or_partner_actor_ttem(partner_item, pkg)
    unknown_item = actor_item.get('unknown') 
    if unknown_item:
        notes_item = unknown_item.get('notes')
        if notes_item:
            ta = ThreatActor()
            ta.description = "Notes:" + escape(notes_item)
            pkg.add_threat_actor(ta)
    
def add_confidentiality_item(confidentiality_item, aa):
    pa = PropertyAffected()
    pa.property_ = LossProperty.TERM_CONFIDENTIALITY
    data_item = confidentiality_item.get('data')
    descriptionOfEventString = ""
    if data_item:
        first = True
        for item in data_item:
            if not first:
                descriptionOfEventString +=  ", "
            else:
                first = False
            variety_item = item.get('variety')
            if not variety_item:
                error("Required 'variety' item is missing in 'attribute/confidentiality/data' item")
            else:
                descriptionOfEventString += variety_item
            amount_item = item.get('amount')
            if amount_item:
                descriptionOfEventString += ": " + str(amount_item)

    notes_item = confidentiality_item.get('notes')
    if notes_item:
        pa.description_of_effect = escape(descriptionOfEventString + "; Notes:" + notes_item)
    else:
        pa.description_of_effect = escape(descriptionOfEventString)
    state_item = confidentiality_item.get('state')
    # how to deal with multiple state values?
    aa.add_property_affected(pa)
    
def add_integrity_item(integrity_item, aa):
    pa = PropertyAffected()
    pa.property_ = LossProperty.TERM_INTEGRITY
    variety_item = integrity_item.get('variety')
    descriptionOfEventString = ""
    if variety_item:
        descriptionOfEventString = ",".join(variety_item)
    notes_item = integrity_item.get('notes')
    if notes_item:
        pa.description_of_effect = escape(descriptionOfEventString + "; Notes:" + notes_item)
    else:
        pa.description_of_effect = escape(descriptionOfEventString)
    # data_disclosure
    aa.add_property_affected(pa)
    
def map_duration_unit_item_to_loss_duration(duration_unit_item):
    if duration_unit_item == "NA":
        return LossDuration.TERM_UNKNOWN
    elif duration_unit_item == "Months" or duration_unit_item == "Years" or duration_unit_item == "Never":
        warn("%s found, using LossDuration.Permanent", duration_unit_item)
        return LossDuration.TERM_PERMANENT
    else:
        try:
            return LossDuration(duration_unit_item)
        except:
            warn("'%s' in 'duration' item not mapped - not using controlled vocab, use as is", duration_unit_item)
            return VocabString(duration_unit_item)
    
def add_availability_item(availability_item, aa):
    pa = PropertyAffected()
    pa.property_ = LossProperty.TERM_AVAILABILITY
    duration_item = availability_item.get('duration')
    if duration_item:
        duration_unit_item = duration_item.get('unit')
        if not duration_unit_item:
            error("Required 'unit' item is missing in 'availability/duration' item")
        else:
            pa.duration_of_availability_loss = map_duration_unit_item_to_loss_duration(duration_unit_item)
    variety_item = availability_item.get('variety')
    if variety_item:
        if len(variety_item) > 1:
            warn("Only 1 AvailabilityLossType allowed - choosing first")
        if variety_item[0] == 'Other':
            pa.type_of_availability_loss = AvailabilityLossType('Unknown')
        else:
            pa.type_of_availability_loss = AvailabilityLossType(variety_item[0])
    notes_item = availability_item.get('notes')
    if notes_item:
        pa.description_of_effect = "Notes: " + escape(notes_item)
    aa.add_property_affected(pa)     

def add_attribute_item(attribute_item, aa):
    confidentiality_item = attribute_item.get('confidentiality')
    if confidentiality_item:
        add_confidentiality_item(confidentiality_item, aa)
    integrity_item = attribute_item.get('integrity')
    if integrity_item:
        add_integrity_item(integrity_item, aa)
    availability_item = attribute_item.get('availability')
    if availability_item:
        add_availability_item(availability_item, aa)
        
def convert_variety_item_to_asset_type(item):
    indexOfDash = item.find("-")
    return item[indexOfDash + 2:]

def map_variety_item_to_asset_type(item):
    if item == "S - Authentication" or item == "S - Code repository" or item == "S - VM host" or item == "T - Other":
        warn("'%s' in 'asset/variety' item not mapped - not using controlled vocab, use as is", item)
        return VocabString(item)
        # return AssetType.TERM_UNKNOWN
    elif item == "S - Other":
        return AssetType.TERM_SERVER
    elif item == "N - Other":
        return AssetType.TERM_NETWORK
    elif item == "U - Other":
        return AssetType.TERM_USER_DEVICE
    elif item == "M - Other":
        return AssetType.TERM_MEDIA
    elif item == "P - System admin":
        return AssetType.TERM_ADMINISTRATOR
    elif item == "P - Other":
        return AssetType.TERM_PERSON
    elif item == "Unknown":
        return AssetType.TERM_UNKNOWN
    else: 
        return AssetType(convert_variety_item_to_asset_type(item))
    
def map_management_item_to_management_class(management_item):
    if management_item == "Internal":
        return ManagementClass.TERM_INTERNALLYMANAGED
    elif management_item == "External":
        return ManagementClass.TERM_EXTERNALLYMANAGEMENT
    elif management_item == "Unknown":
        return ManagementClass.TERM_UNKNOWN
    else:
        warn("'%s' in 'management' item not mapped - not using controlled vocab, use as is", management_item )
        return VocabString(management_item)

def map_ownership_item_to_ownership_class(ownership_item):
    if ownership_item == "Victim":
        return OwnershipClass.TERM_INTERNALLYOWNED
    elif ownership_item == "Employee":
        return OwnershipClass.TERM_EMPLOYEEOWNED
    elif ownership_item == "Partner":
        return OwnershipClass.TERM_PARTNEROWNED
    elif ownership_item == "Customer":
        return OwnershipClass.TERM_CUSTOMEROWNED
    elif ownership_item == "Unknown":
        return OwnershipClass.TERM_UNKNOWN
    else:
        warn("'%s' in 'ownership' item not mapped - not using controlled vocab, use as is", ownership_item)
        return VocabString(ownership_item)
                                           
def map_hosting_item_to_location_class(hosting_item):
    if hosting_item == "Internal":
        return LocationClass.TERM_INTERNALLYLOCATED
    elif hosting_item == "External shared" or hosting_item == "External dedicated" or hosting_item == "External":
        return LocationClass.TERM_EXTERNALLYLOCATED
    elif hosting_item == "Unknown":
        return LocationClass.TERM_UNKNOWN
    else: 
        warn("'%s' in 'hosting' item not mapped - not using controlled vocab, use as is", hosting_item )
        return VocabString(hosting_item)
   
def add_asset_item(asset_item, attribute_item, incident):
    assets_item = asset_item.get("assets")
    if not assets_item:
        error("VERIS warning: 'assets' item is missing in 'asset' item")
    else:
        notes_item = asset_item.get('notes')
        management_item = asset_item.get('management')
        if management_item:
            managementClass = map_management_item_to_management_class(management_item)
        ownership_item = asset_item.get('ownership')
        if ownership_item:
            ownershipClass = map_ownership_item_to_ownership_class(ownership_item)
        hosting_item = asset_item.get("hosting")
        if hosting_item:
            locationClass = map_hosting_item_to_location_class(hosting_item)
        # cloud
        for item in assets_item:
            aa = AffectedAsset()
            variety_item = item.get('variety')
            if not variety_item:
                error("Required 'variety' item is missing in 'asset/assets' item")
            else:
                aa.type_ = map_variety_item_to_asset_type(variety_item)
            asset_description = ""
            if notes_item:
                asset_description += "General Notes: " + notes_item
            amount_item = item.get('amount')
            if amount_item:
                asset_description += "Number of Assets: " + str(amount_item)
            aa.description = escape(asset_description)
            # same locationClass, managementClass and ownershipClass for each asset
            if management_item:
                aa.management_class = managementClass
            if ownership_item:
                aa.ownership_class = ownershipClass
            if hosting_item:
                aa.location_class = locationClass
            if attribute_item:
                # consider not recomputing this for each asset
                add_attribute_item(attribute_item, aa)
            incident.add_affected_asset(aa)
            
def add_campaign_item(campaign_id_item, pkg):
    campaign = Campaign()
    campaign.names = Names()
    campaign.names.append(VocabString(campaign_id_item))
    pkg.add_campaign(campaign)

def add_confidence_item(confidence_item, incident):
    confidence = Confidence(confidence_item);
    incident.confidence(confidence)
   
def map_cost_corrective_action_item_to_high_medium_low(cost_corrective_action_item):
    if cost_corrective_action_item == "Simple and cheap":
        return HighMediumLow.TERM_LOW
    elif cost_corrective_action_item == "Something in-between":
        return HighMediumLow.TERM_MEDIUM
    elif cost_corrective_action_item == "Difficult and expensive":
        return HighMediumLow.TERM_HIGH
    elif cost_corrective_action_item == "Unknown":
        return HighMediumLow.TERM_UNKNOWN
    else:
        warn("'%s' is not a legal cost_corrective_action item, using HighMediumLow.NONE", cost_corrective_action_item)
        return HighMediumLow.TERM_NONE

def add_coa_items(corrective_action_item, cost_corrective_action_item, pkg):
    coa = CourseOfAction()
    if corrective_action_item:
        coa.title = corrective_action_item
    if cost_corrective_action_item:
        cost = Statement()
        cost.value = map_cost_corrective_action_item_to_high_medium_low(cost_corrective_action_item)
        coa.cost = cost
    pkg.coa = coa
    
def convert_discovery_method_item(item):
    indexOfDash = item.find("-")
    return item[indexOfDash + 2:].title()

def add_loss_items(loss_item, ia):
    for item in loss_item:
        dis = DirectImpactSummary()
        rating_item = item.get("rating")
        if rating_item:
            dis.business_mission_disruption = ImpactRating(rating_item)

def add_impact_item(impact_item, incident):
    ia = ImpactAssessment()
    iso_currency_code_item = impact_item.get("iso_currency_code")
    
    amount_item = impact_item.get("overall_amount")
    if not amount_item:
        warn("'overall_amount' item is missing from 'impact' item, skipping TotalLossEstimation")
    else:
        tle = TotalLossEstimation()
        atle = LossEstimation()
        if not iso_currency_code_item:
            warn("'iso_currency_code' item is missing from 'impact' item, assuming USD")
            atle.iso_currency_code = "USD"
        else:
            atle.iso_currency_code = iso_currency_code_item
        atle.amount = amount_item        
        tle.actual_total_loss_estimation = atle
        ia.total_loss_estimation = tle
    loss_item = impact_item.get("loss")
    if loss_item:
        add_loss_items(loss_item, ia)
    overall_rating_item = impact_item.get("overall_rating")
    if overall_rating_item:
        ia.impact_qualification = ImpactQualification(overall_rating_item)
    incident.impact_assessment = ia

def map_discovey_method(discovery_method_item):
    if  discovery_method_item == 'Other' or discovery_method_item == 'Unknown':
        return DiscoveryMethod.TERM_UNKNOWN
    elif discovery_method_item == 'Int - HIDS':
        return DiscoveryMethod.TERM_HIPS
    elif discovery_method_item == 'Int - NIDS':
        return DiscoveryMethod.TERM_NIDS
    elif discovery_method_item == 'Int - reported by user':
        return DiscoveryMethod.TERM_USER
    elif discovery_method_item == 'Ext - actor disclosure':
        return DiscoveryMethod.TERM_AGENT_DISCLOSURE
    elif discovery_method_item == 'Int - IT audit':
        return DiscoveryMethod.TERM_IT_AUDIT
    else:
        try:
            return DiscoveryMethod(convert_discovery_method_item(discovery_method_item))
        except:
            warn("'%s' in 'discovery_method' item not mapped - not using controlled vocab, use as is", discovery_method_item )
            return VocabString(discovery_method_item)
          
def add_analyst_item(analyst_item, incident):
    insrc = InformationSource()
    analyst_identity = CIQIdentity3_0Instance()
    identity_spec = STIXCIQIdentity3_0()
    analyst_identity.specification = identity_spec
    if analyst_item:
        partyName = PartyName()
        partyName.add_name_line(analyst_item)
        identity_spec.party_name = partyName
    insrc.identity = analyst_identity
    incident.reporter = insrc
  
def add_plus_item(plus_item, incident, pkg):
    analyst_item = plus_item.get("analyst")
    if analyst_item:
        add_analyst_item(analyst_item, incident)
    created_item = plus_item.get('created')
    if created_item:
        pkg.timestamp = created_item
    modified_item = plus_item.get('modified')
    if modified_item:
        incident.timestamp = modified_item

def map_security_incident_item_to_security_compromise(security_incident_item):
    if security_incident_item == "Confirmed":
        return SecurityCompromise.TERM_YES
    elif security_incident_item == "Suspected":
        return SecurityCompromise.TERM_SUSPECTED
    else:
        warn("'%s' in 'security_incident' item not mapped - not using controlled vocab, use as is", security_incident_item)
        return VocabString(security_incident_item)

# how are more than one related incidents specified?
def add_related_incidents_item(related_incidents_item, incident):
    # assuming only one id 
    rIncident = Incident()
    externalID = ExternalID()
    externalID.value = related_incidents_item
    externalID.source = "VERIS"  
    rIncident.add_external_id(externalID)
    incident.related_incidents.append(rIncident)
    
# may need to split reference_item on ';'
def add_information_source_items(reference_item, source_id_item, schema_version_item, incident):
    insrc = InformationSource()
    if reference_item:
        for item in reference_item.split(';'):
            insrc.add_reference(item.strip())
    if source_id_item  or schema_version_item:
        insrc.tools = ToolInformationList()
    if source_id_item:  
        insrc.identity = Identity()  
        insrc.identity.name = source_id_item
        tool = ToolInformation()
        tool.name = "veris2stix"
        tool.vendor = "MITRE"
        tool.version = __version__
        insrc.tools.append(tool)
    if schema_version_item:
        tool = ToolInformation()
        tool.name = "VERIS schema"
        tool.vendor = "Verizon"
        tool.version = schema_version_item
        insrc.tools.append(tool)
    incident.information_source = insrc   

def convert_items_to_datetime(year_item, month_item, day_item, time_item):
    # assume month or day of 1 if they aren't specified....
    date_string = str(year_item) + "-" + str(month_item) + "-" + str(day_item) + " " + time_item
    try:
        return dateutil.parser.parse(date_string)
    except ValueError:
        error("Value Error in '%s', skipping item", date_string)
        return None
    
def convert_time_item_to_datetime(incident_time_item):
    day_item = incident_time_item.get("day")
    month_item = incident_time_item.get("month")
    time_item = incident_time_item.get("time")
    year_item = incident_time_item.get("year")
    if not time_item:
        time_item = "00:00:00"
        precision = "day"
    if not day_item:
        day_item = 1
        precision = "month"
    if not month_item:
        month_item = 1
        precision = "year"
    if not year_item:
        error("Required 'year' item is missing in 'incident' item, skipping item")
        return None
    dateTime = DateTimeWithPrecision()
    dateTime.precision = precision
    value = convert_items_to_datetime(year_item, month_item, day_item, time_item)
    if not value:
        return None
    dateTime.value = value
    return dateTime
    
def convert_value_unit_to_datetime(item, incident_date_time, fieldname):
    unit_item = item.get("unit")
    if unit_item == "Unknown":
        warn("'%s' item contains 'Unknown'", fieldname)
        return None
    value_item = item.get("value")
    # if no values, assume an half-way point to the next largest unit, except for years - 2 chosen somewhat arbitrarily
    if not value_item:
        imprecise = True
        if unit_item == "Seconds":
            value_item = 30           
            warn("'%s' item contains only 'Seconds' as unit information - assuming value is 30 seconds", fieldname)
        elif unit_item == "Minutes":
            value_item = 30
            warn("'%s' item contains only 'Minutes' as unit information - assuming value is 30 minutes", fieldname)
        elif unit_item == "Hours":
            value_item = 12
            warn("'%s' item contains only 'Hours' as unit information - assuming value is 12 hours", fieldname)
        elif unit_item == "Days":
            value_item = 3
            warn("'%s' item contains only 'Days' as unit information - assuming value is 3 days", fieldname)
        elif unit_item == "Weeks":
            value_item = 2
            warn("'%s' item contains only 'Weeks' as unit information - assuming value is 2 weeks", fieldname)
        elif unit_item == "Months":
            value_item = 6
            warn("'%s' item contains only 'Months' as unit information - assuming value is 6 months", fieldname)
        elif unit_item == "Years":
            value_item = 2
            warn("'%s' item contains only 'Years' as unit information - assuming value is 2 years", fieldname)
        elif unit_item ==  "Never":
            warn("'%s' item contains 'Never' as unit information - returning 0", fieldname)
            return 0
        elif unit_item == "NA":
            warn("'%s' item contains 'NA' as unit information - returning 0", fieldname)
            return 0
    else:
        imprecise = False
    if unit_item == "Seconds":
        if imprecise:
            precision = "minute"
        else:
            precision = "second"
        delta = timedelta(0, value_item)
    elif unit_item == "Minutes":
        if imprecise:
            precision = "hour"
        else:
            precision = "minute"
        delta = timedelta(0, 0, 0, 0, value_item)
    elif unit_item == "Hours":
        if imprecise:
            precision = "day"
        else:
            precision = "hour"
        delta = timedelta(0, 0, 0, 0, 0, value_item)
    elif unit_item == "Days":
        precision = "day"
        delta = timedelta(value_item)
    elif unit_item == "Weeks":
        precision = "month"
        delta = timedelta(0, 0, 0, 0, 0, 0, value_item)
    elif unit_item == "Months":
        if imprecise:
            precision = "year"
        else:
            precision = "month"
        delta = timedelta(0, 0, 0, 0, 0, 0, value_item * 4)
    elif unit_item == "Years":
        precision = "year"
        delta = timedelta(value_item * 365)
    elif unit_item ==  "Never":
        warn("'%s' item contains 'Never' as unit information, but also a value, skipping", fieldname)
        return None
    elif unit_item == "NA":
        warn("'%s' item contains 'NA' as unit information, but also a value, skipping", fieldname)
        return None
    dateTime = DateTimeWithPrecision()
    dateTime.precision = precision
    if fieldname == "compromise":
        dateTime.value = incident_date_time.value - delta
    else:
        dateTime.value = incident_date_time.value + delta
    return dateTime
    
# timedelta([days[, seconds[, microseconds[, milliseconds[, minutes[, hours[, weeks]]]]]]])
      
def add_timeline_item(timeline_item, incident):
    incident_time_item = timeline_item.get('incident')
    if not incident_time_item:
        error("Required 'incident' item is missing in 'timeline' item, skipping item")
        return None 
    incident_date_time = convert_time_item_to_datetime(incident_time_item)
    if not incident_date_time:
        return None
    complete = 0
    time = Time() 
    time.initial_compromise = incident_date_time   
    complete += 1
    compromise_item = timeline_item.get('compromise')
    if compromise_item:
        dt = convert_value_unit_to_datetime(compromise_item, incident_date_time, 'compromise')
        if dt:
            complete += 1
        time.first_malicious_action = dt
    discovery_item = timeline_item.get('discovery')
    containment_item = timeline_item.get('containment')
    if discovery_item:
        dt = convert_value_unit_to_datetime(discovery_item, incident_date_time, 'discovery')
        if dt:
            complete += 1
        time.incident_discovery =  dt
    exfiltration_item = timeline_item.get('exfiltration')
    if exfiltration_item:
        dt = convert_value_unit_to_datetime(exfiltration_item, incident_date_time, 'exfiltration')
        if dt:
            complete += 1
        time.first_data_exfiltration = dt
    # according to Kevin Thompson (Verizon), containment starts at discovery.  Use others if it isn't available 
    if containment_item:
        if time.incident_discovery:
            timePoint = time.incident_discovery
        elif time.first_data_exfiltration:
            timePoint = time.first_data_exfiltration
            warn("the 'containment' item is specified in the 'timeline' item, but the 'discovery' item is missing or not usable. Using the exfiltration datetime")
        else:
            timePoint = incident_date_time
            warn("the 'containment' item is specified in the 'timeline' item, but the 'discovery' and 'exfitration' items are missing or not usable. Using the incident datetime")
        dt = convert_value_unit_to_datetime(containment_item, timePoint, 'containment')
        if dt:
            complete += 1
        time.containment_achieved = dt
    incident.time = time
    if complete > 3:
        error("Found a possible good timeline")

def add_victim_item(victim_item, incident):
    global targets_item
    victim_identity = CIQIdentity3_0Instance()
    identity_spec = STIXCIQIdentity3_0()
    victim_identity.specification = identity_spec
    if targets_item:
        for item in targets_item:
            victim_identity.add_role(item)
    country_item = victim_item.get('country')
    if not country_item:
        error("Required 'country' item is missing in 'victim' item")
    else:  
        for c in country_item:
            address = Address()
            address.country = Country()
            address.country.add_name_element(c)
            state_item = victim_item.get('state')
            if state_item:
                address.administrative_area = AdministrativeArea()
                address.administrative_area.add_name_element(state_item)
            identity_spec.add_address(address)
    # no organisationInfo details - https://github.com/STIXProject/python-stix/issues/108 
    if victim_item.get("employee_count"):
        warn("'victim/employee_count' item not handled, yet")
    if victim_item.get("industry"):
        warn("'victim/industry' item not handled, yet")
    if victim_item.get("revenue"):
        warn("'victim/revenue' item not handled, yet")
    victim_id_item = victim_item.get('victim_id')
    if victim_id_item:
        partyName = PartyName()
        # id might be inappropriate for name
        partyName.add_name_line(victim_id_item)
        identity_spec.party_name = partyName
        
    incident.add_victim(victim_identity)
    
def get_ids(list_):
    ids = []
    for thing in list_:
        if thing.id_ :
            ids.append(thing._id)
    return ids

def add_related_ttps(pkg):
    if pkg.ttps:
        ttp_ids = get_ids(pkg.ttps.ttps)
        for thing in pkg.incidents:
            related_ttps = LeveragedTTPs()
            for ID in ttp_ids:
                related_ttps.append(RelatedTTP(TTP(idref=ID)))
            thing.leveraged_ttps = related_ttps
        for thing in pkg.threat_actors:
            related_ttps = ObservedTTPs()
            for ID in ttp_ids:
                related_ttps.append(RelatedTTP(TTP(idref=ID)))
            thing.observed_ttps = related_ttps
        # indicators
        
def add_related_threat_actors(pkg):
    if pkg.threat_actors:
        threat_actors_ids = get_ids(pkg.threat_actors)
        for thing in pkg.incidents:
            relatedThreatActors = AttributedThreatActors()
            for ID in threat_actors_ids:
                relatedThreatActors.append(RelatedThreatActor(ThreatActor(idref=ID)))
            thing.attributed_threat_actors = relatedThreatActors
        # campaigns?
            
def add_related(pkg):
    add_related_ttps(pkg)
    add_related_threat_actors(pkg)
    # course of actions
    # indicators
    # observables

def add_cve_info(pkg):
    global cve_info
    if cve_info != []:
        processed_ttps = []
        for x in cve_info:
            et = ExploitTarget()
            for cve in x.get('cves'):
                v = Vulnerability()
                v.cve_id = cve
                et.add_vulnerability(v)
            pkg.add_exploit_target(et)
            ttp = x.get('related_ttp')
            if ttp not in processed_ttps:
                if not ttp.exploit_targets:
                    ttp.exploit_targets = ExploitTargets()
                ttp.exploit_targets.append(RelatedExploitTarget(ExploitTarget(idref=et._id)))
                processed_ttps.append(ttp)
        
def convert_file(ifn, ofn, vcdb):
    global cve_info
    global targets_item
    cve_info = []
    targets_item = None
    with open(ifn) as json_data:
        veris_item = json.load(json_data)
        json_data.close()
    schema_version_item = veris_item.get("schema_version")
    if not schema_version_item:
        error("The 'schema_version' item is required")
    elif not (schema_version_item == "1.3" or schema_version_item == "1.3.0"):
        error("This converter is for VERIS schema version 1.3.  This file has schema version " + schema_version_item)
        return
    pkg = STIXPackage()
    action_item = veris_item.get('action')
    if not action_item:
        error("The 'action' item is required")
    else:
        add_action_item(action_item, pkg)
    add_cve_info(pkg)
    actor_item = veris_item.get('actor')
    if not actor_item:
        error("The 'actor' item is required")
    else:
        add_actor_item(actor_item, pkg)
    incident = Incident()
    pkg.add_incident(incident)
    asset_item = veris_item.get('asset')
    if not asset_item:
        error("The 'asset' item is required")
    else:
        attribute_item = veris_item.get('attribute')
        add_asset_item(asset_item, attribute_item, incident)
    # added as 1.3
    campaign_id_item = veris_item.get('campaign_id')
    if campaign_id_item:
        add_campaign_item(campaign_id_item, pkg)
    confidence_item = veris_item.get('confidence')
    if confidence_item:
        add_confidence_item(confidence_item, incident)
    #control_failure - not found in data
    if veris_item.get('control_failure'):
        warn("'control_failure' item not handled, yet")
    corrective_action_item = veris_item.get('corrective_action')
    cost_corrective_action_item = veris_item.get('cost_corrective_action')
    if corrective_action_item  or cost_corrective_action_item:
        add_coa_items(corrective_action_item, cost_corrective_action_item, pkg)
    discovery_method_item = veris_item.get('discovery_method')
    if not discovery_method_item:
        error("The 'discovery_method' item is required")
    else:
        incident.add_discovery_method(map_discovey_method(discovery_method_item))
    discovery_notes_item = veris_item.get('discovery_notes') 
    if discovery_notes_item:
        warn("'discovery_notes' item not handled yet")
    impact_item = veris_item.get('impact')    
    if impact_item:
        add_impact_item(impact_item, incident)  
    incident_id_item = veris_item.get('incident_id') 
    if not incident_id_item:
        error("The 'incident_id' item is required")
    else:
        external_id = ExternalID()
        external_id.value = incident_id_item
        external_id.source = "VERIS" 
        incident.add_external_id(external_id)
    notes_item = veris_item.get('notes')      
    if notes_item:
        pkg.stix_header = STIXHeader()
        pkg.stix_header.title = "Notes: " + notes_item
    # plus item for records from VCDB have some known useful information 
    if vcdb:
        plus_item = veris_item.get('plus')
        if plus_item:
            add_plus_item(plus_item, incident, pkg)
    # removed as of 1.3 - see campaign_id
    # related_incidents_item = veris_item.get('related_incidents')
    # if related_incidents_item:
    #    add_related_incidents_item(related_incidents_item, incident)
    
    security_incident_item = veris_item.get('security_incident')
    if not security_incident_item:
        error("The 'security_incident' item is required")
    else:
        incident.security_compromise = map_security_incident_item_to_security_compromise(security_incident_item)
    reference_item = veris_item.get('reference')
    source_id_item = veris_item.get('source_id')
    if source_id_item or reference_item:
        add_information_source_items(reference_item, source_id_item, schema_version_item, incident)
    summary_item = veris_item.get('summary')
    if summary_item:
        incident.title = summary_item
    #targeted_item = veris_item.get('targeted')
    #if targeted_item:   
    timeline_item = veris_item.get('timeline')
    if not timeline_item:
        error("The 'timeline' item is required")
    else:
        add_timeline_item(timeline_item, incident)
    victim_item = veris_item.get('victim')
    if victim_item:
        add_victim_item(victim_item, incident)
    add_related(pkg)
    if not ofn:
        stixXML = sys.stdout
    else:
        stixXML = open(ofn, 'wb')
    stixXML.write(pkg.to_xml())
    stixXML.close()


def convert(files, outdir, vcdb=True):
    for fn in files:
        info("Processing %s" % (fn))
        ifn = os.path.split(fn)[1]
        ofn = os.path.join(outdir, ifn[:-5] + ".xml")
        convert_file(fn, ofn, vcdb)


def get_files(path):
    '''Returns a list of filenames to convert'''
    files = []
    if not path:
        return files

    try:
        for fn in os.listdir(path):
            if fn.lower().endswith(".json"):
                file_path = os.path.join(path, fn)
                files.append(file_path)
    except OSError as ex:
        files = [path] if path.lower().endswith(".json") else []

    return files


def main():
    parser = argparse.ArgumentParser(description="VERIS-to-STIX Converter")
    parser.add_argument("--infile", dest="infile", default=None, help="Path to input file")
    parser.add_argument("--indir", dest="indir", default=None, help="Path to directory containing input files")
    parser.add_argument("--outdir", dest="outdir", default=".", help="Directory for exported STIX documents")
    parser.add_argument("--from-vcdb", dest="from_vcdb", default=True, action="store_true", help="The input documents are from VCDB (default: True)")

    args = parser.parse_args()
    if not (args.infile or args.indir):
        parser.print_help()
        sys.exit(EXIT_ERROR)

    if args.infile and args.indir:
        parser.print_help()
        sys.exit(EXIT_ERROR)

    if args.infile:
        files = get_files(args.infile)
    else:
        files = get_files(args.indir)

    if files:
        convert(files, args.outdir, args.from_vcdb)
    else:
        error("No json files to process. Exiting.")

if __name__ == '__main__':
    main()
