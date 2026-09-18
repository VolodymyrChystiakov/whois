package net.ripe.db.whois.update.handler.validator.outofregion;

import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.grs.AuthoritativeResource;
import net.ripe.db.whois.common.grs.AuthoritativeResourceData;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.Principal;
import net.ripe.db.whois.update.authentication.Subject;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static net.ripe.db.whois.common.rpsl.ObjectType.AUT_NUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.INET6NUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.INETNUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.ROUTE;
import static net.ripe.db.whois.common.rpsl.ObjectType.ROUTE6;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class OutOfRegionObjectValidatorTest {

    @Mock AuthoritativeResourceData authoritativeResourceData;
    @Mock AuthoritativeResource authoritativeResource;
    @Mock PreparedUpdate update;
    @Mock UpdateContext updateContext;
    @Mock Subject subject;

    @Test
    public void default_configuration_rejects_out_of_region_objects() {
        final OutOfRegionObjectValidator validator = validator(false);

        for (final ObjectType objectType : new ObjectType[]{AUT_NUM, ROUTE, ROUTE6}) {
            final RpslObject object = object(objectType);
            when(update.getUpdatedObject()).thenReturn(object);
            when(updateContext.getSubject(update)).thenReturn(subject);
            when(subject.hasPrincipal(Principal.OVERRIDE_MAINTAINER)).thenReturn(false);
            when(subject.hasPrincipal(Principal.RS_MAINTAINER)).thenReturn(false);
            stubAuthoritativeResource(objectType, false);

            final List<Message> messages = validator.performValidation(update, updateContext);

            assertThat(messages, hasSize(1));
            assertThat(messages.get(0), is(UpdateMessages.cannotCreateOutOfRegionObject(objectType)));
        }
    }

    @Test
    public void anrr_configuration_allows_out_of_region_objects_without_changing_authentication() {
        final OutOfRegionObjectValidator validator = validator(true);

        final List<Message> messages = validator.performValidation(update, updateContext);

        assertThat(messages, empty());
        verifyNoInteractions(updateContext, authoritativeResourceData, authoritativeResource, subject);
    }

    @Test
    public void in_region_objects_remain_allowed() {
        final OutOfRegionObjectValidator validator = validator(false);
        when(update.getUpdatedObject()).thenReturn(object(ROUTE));
        when(updateContext.getSubject(update)).thenReturn(subject);
        when(subject.hasPrincipal(Principal.OVERRIDE_MAINTAINER)).thenReturn(false);
        when(subject.hasPrincipal(Principal.RS_MAINTAINER)).thenReturn(false);
        stubAuthoritativeResource(ROUTE, true);

        final List<Message> messages = validator.performValidation(update, updateContext);

        assertThat(messages, empty());
    }

    @Test
    public void override_and_rs_principals_keep_the_existing_escape_hatch() {
        final OutOfRegionObjectValidator validator = validator(false);
        when(updateContext.getSubject(update)).thenReturn(subject);
        when(subject.hasPrincipal(Principal.OVERRIDE_MAINTAINER)).thenReturn(true);

        final List<Message> messages = validator.performValidation(update, updateContext);

        assertThat(messages, empty());
        verifyNoInteractions(authoritativeResourceData, authoritativeResource);
    }

    @Test
    public void only_autnum_route_and_route6_are_subject_to_this_rule() {
        assertThat(validator(false).getTypes(), containsInAnyOrder(AUT_NUM, ROUTE, ROUTE6));
        assertThat(validator(false).getTypes(), hasSize(3));
    }

    private OutOfRegionObjectValidator validator(final boolean allowOutOfRegion) {
        return new OutOfRegionObjectValidator(authoritativeResourceData, allowOutOfRegion);
    }

    private void stubAuthoritativeResource(final ObjectType objectType, final boolean inRegion) {
        when(authoritativeResourceData.getAuthoritativeResource()).thenReturn(authoritativeResource);
        if (objectType == ROUTE || objectType == ROUTE6) {
            when(authoritativeResource.isRouteMaintainedInRirSpace(any(RpslObject.class))).thenReturn(inRegion);
        } else {
            when(authoritativeResource.isMaintainedInRirSpace(any(RpslObject.class))).thenReturn(inRegion);
        }
    }

    private RpslObject object(final ObjectType objectType) {
        switch (objectType) {
            case AUT_NUM:
                return RpslObject.parse("aut-num: AS64496\nsource: TEST");
            case ROUTE:
                return RpslObject.parse("route: 192.0.2.0/24\norigin: AS64496\nsource: TEST");
            case ROUTE6:
                return RpslObject.parse("route6: 2001:db8::/32\norigin: AS64496\nsource: TEST");
            case INETNUM:
                return RpslObject.parse("inetnum: 192.0.2.0 - 192.0.2.255\nsource: TEST");
            case INET6NUM:
                return RpslObject.parse("inet6num: 2001:db8::/32\nsource: TEST");
            default:
                throw new IllegalArgumentException("Unsupported test object type: " + objectType);
        }
    }
}
