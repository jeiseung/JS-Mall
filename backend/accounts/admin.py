from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from django.db import transaction, IntegrityError
from .models import User
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)
from rangefilter.filters import DateRangeFilter, DateTimeRangeFilter


class UserAdmin(BaseUserAdmin):
    fieldsets = (
        (None, {"fields": ("email", "password", "firebase_uid")}),
        (_("Personal info"), {"fields": ("username",)}),
        (_("Important dates"), {"fields": ("last_login", "start_date")}),
        (
            _("Email verification"),
            {"fields": ("email_verification_code", "is_email_verified")},
        ),
        (_("Permissions"), {"fields": ("is_active", "is_staff", "user_permissions")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "username", "password1", "password2"),
            },
        ),
    )
    list_display = (
        "email",
        "username",
        "is_email_verified",
        "is_active",
        "last_login",
        "start_date",
    )
    list_filter = (
        "is_active",
        "is_email_verified",
        ("last_login", DateRangeFilter),
        ("start_date", DateRangeFilter),
    )
    search_fields = ("email", "username")
    ordering = ("email",)
    filter_horizontal = (
        "groups",
        "user_permissions",
    )
    readonly_fields = (
        "email",
        "email_verification_code",
        "firebase_uid",
        "last_login",
        "start_date",
    )

    # Action to toggle is_email_verified field
    @admin.action(description="Toggle email verification status")
    def toggle_email_verification(self, request, queryset):
        updated_count = 0
        for user in queryset:
            user.is_email_verified = not user.is_email_verified
            user.save()
            updated_count += 1
        self.message_user(
            request, f"{updated_count} 사용자의 이메일 인증 상태가 변경되었습니다."
        )

    def delete_model(self, request, obj):
        try:
            with transaction.atomic():
                self._delete_related_tokens(obj)
                super().delete_model(request, obj)
        except IntegrityError as e:
            self.message_user(
                request,
                f"사용자 {obj.email} 삭제 중 오류 발생: {str(e)}",
                level="error",
            )

    def delete_queryset(self, request, queryset):
        try:
            with transaction.atomic():
                for obj in queryset:
                    self._delete_related_tokens(obj)
                super().delete_queryset(request, queryset)
        except IntegrityError as e:
            self.message_user(
                request, f"사용자 삭제 중 오류 발생: {str(e)}", level="error"
            )

    def _delete_related_tokens(self, user):
        OutstandingToken.objects.filter(user=user).delete()
        BlacklistedToken.objects.filter(token__user=user).delete()

    # Register the action in actions list
    actions = ["toggle_email_verification"]


admin.site.register(User, UserAdmin)
