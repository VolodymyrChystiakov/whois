package net.ripe.db.whois.update.generator;

import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.grs.AuthoritativeResource;
import net.ripe.db.whois.common.grs.AuthoritativeResourceData;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.Operation;
import net.ripe.db.whois.update.domain.Update;
import net.ripe.db.whois.update.domain.UpdateContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static net.ripe.db.whois.common.domain.CIString.ciString;
import static net.ripe.db.whois.common.rpsl.ObjectType.AUT_NUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.INET6NUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.INETNUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.ROUTE;
import static net.ripe.db.whois.common.rpsl.ObjectType.ROUTE6;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SourceGeneratorTest {

    @Mock AuthoritativeResourceData authoritativeResourceData;
    @Mock AuthoritativeResource authoritativeResource;
    @Mock RpslObjectDao rpslObjectDao;
    @Mock Update update;
    @Mock UpdateContext updateContext;

    @Test
    public void default_configuration_rewrites_out_of_region_objects_to_nonauth() {
        when(update.getOperation()).thenReturn(Operation.UNSPECIFIED);

        for (final ObjectType objectType : new ObjectType[]{AUT_NUM, ROUTE, ROUTE6}) {
            assertSource(objectType, false, false, "TEST-NONAUTH");
        }
    }

    @Test
    public void anrr_configuration_preserves_main_source_for_out_of_region_objects() {
        when(update.getOperation()).thenReturn(Operation.UNSPECIFIED);

        for (final ObjectType objectType : new ObjectType[]{AUT_NUM, ROUTE, ROUTE6}) {
            assertSource(objectType, false, true, "TEST");
        }
    }

    @Test
    public void in_region_objects_remain_unchanged() {
        when(update.getOperation()).thenReturn(Operation.UNSPECIFIED);

        for (final ObjectType objectType : new ObjectType[]{AUT_NUM, ROUTE, ROUTE6}) {
            final RpslObject object = object(objectType, "TEST");
            stubAuthoritativeResource(objectType, true);

            final RpslObject result = generator(false).generateAttributes(null, object, update, updateContext);

            assertThat(result, sameInstance(object));
        }
    }

    @Test
    public void in_region_nonauth_source_is_still_normalized_to_main_source() {
        when(update.getOperation()).thenReturn(Operation.UNSPECIFIED);
        final RpslObject object = object(ROUTE, "TEST-NONAUTH");
        stubAuthoritativeResource(ROUTE, true);

        final RpslObject result = generator(true).generateAttributes(null, object, update, updateContext);

        assertThat(result.getValueForAttribute(AttributeType.SOURCE), is(ciString("TEST")));
    }

    @Test
    public void delete_does_not_rewrite_out_of_region_object() {
        when(update.getOperation()).thenReturn(Operation.DELETE);
        final RpslObject object = object(ROUTE, "TEST");

        final RpslObject result = generator(false).generateAttributes(null, object, update, updateContext);

        assertThat(result, sameInstance(object));
        verifyNoInteractions(authoritativeResourceData, authoritativeResource);
    }

    @Test
    public void inetnum_and_inet6num_authority_semantics_are_not_changed() {
        for (final ObjectType objectType : new ObjectType[]{INETNUM, INET6NUM}) {
            final RpslObject object = object(objectType, "TEST");

            final RpslObject result = generator(true).generateAttributes(null, object, update, updateContext);

            assertThat(result, sameInstance(object));
        }

        verifyNoInteractions(authoritativeResourceData, authoritativeResource);
    }

    private void assertSource(final ObjectType objectType, final boolean inRegion, final boolean allowOutOfRegion,
                              final String expectedSource) {
        final RpslObject object = object(objectType, "TEST");
        stubAuthoritativeResource(objectType, inRegion);

        final RpslObject result = generator(allowOutOfRegion).generateAttributes(null, object, update, updateContext);

        assertThat(result.getValueForAttribute(AttributeType.SOURCE), is(ciString(expectedSource)));
    }

    private void stubAuthoritativeResource(final ObjectType objectType, final boolean inRegion) {
        when(authoritativeResourceData.getAuthoritativeResource()).thenReturn(authoritativeResource);
        if (objectType == ROUTE || objectType == ROUTE6) {
            when(authoritativeResource.isRouteMaintainedInRirSpace(any(RpslObject.class))).thenReturn(inRegion);
        } else {
            when(authoritativeResource.isMaintainedInRirSpace(any(RpslObject.class))).thenReturn(inRegion);
        }
    }

    private SourceGenerator generator(final boolean allowOutOfRegion) {
        return new SourceGenerator(authoritativeResourceData, "TEST", "TEST-NONAUTH", rpslObjectDao, allowOutOfRegion);
    }

    private RpslObject object(final ObjectType objectType, final String source) {
        switch (objectType) {
            case AUT_NUM:
                return RpslObject.parse("aut-num: AS64496\nsource: " + source);
            case ROUTE:
                return RpslObject.parse("route: 192.0.2.0/24\norigin: AS64496\nsource: " + source);
            case ROUTE6:
                return RpslObject.parse("route6: 2001:db8::/32\norigin: AS64496\nsource: " + source);
            case INETNUM:
                return RpslObject.parse("inetnum: 192.0.2.0 - 192.0.2.255\nsource: " + source);
            case INET6NUM:
                return RpslObject.parse("inet6num: 2001:db8::/32\nsource: " + source);
            default:
                throw new IllegalArgumentException("Unsupported test object type: " + objectType);
        }
    }
}
