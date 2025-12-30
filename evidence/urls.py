from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('create_case/', views.create_case, name='create_case'),
    path('case/<str:case_id>/', views.case_detail, name='case_detail'),
    path('case/<str:case_id>/get_key/', views.get_key, name='get_key'),
    path('case/<str:case_id>/ingest/', views.ingest_evidence, name='ingest_evidence'),
    path('file/<str:case_id>/<str:file_id>/', views.file_detail, name='file_detail'),
    path('download/<str:case_id>/<str:file_id>/', views.download_decrypted, name='download_decrypted'),
    path('check_integrity/', views.check_integrity, name='check_integrity'),
    path('decrypt/', views.decrypt_evidence, name='decrypt_evidence'),
    path('logs/', views.view_logs, name='view_logs'),
    path('logs/<int:log_id>/', views.log_detail, name='log_detail'),
]
