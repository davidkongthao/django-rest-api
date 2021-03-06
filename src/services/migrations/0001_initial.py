# Generated by Django 4.0.2 on 2022-02-14 08:27

from django.db import migrations, models
import django.db.models.deletion
import phonenumber_field.modelfields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('organizations', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='BusinessOwnerAddress',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('line1', models.CharField(max_length=256)),
                ('line2', models.CharField(blank=True, max_length=256)),
                ('city', models.CharField(max_length=256)),
                ('state', models.CharField(max_length=128)),
                ('country', models.CharField(max_length=128)),
                ('postal_code', models.CharField(max_length=32)),
            ],
            options={
                'db_table': 'services_business_registration__owner__address',
            },
        ),
        migrations.CreateModel(
            name='Domain',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subscription_id', models.CharField(max_length=64)),
                ('domain_name', models.CharField(editable=False, max_length=256, unique=True)),
                ('contact_information', models.JSONField(default=dict)),
                ('purchase_date', models.DateField(auto_now_add=True)),
                ('expiration_date', models.DateField()),
                ('privacy_enabled', models.BooleanField(default=True)),
                ('is_billed_annually', models.BooleanField(default=True)),
                ('auto_renew_enabled', models.BooleanField(default=True)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='organizations.organization')),
            ],
            options={
                'verbose_name': 'Domain',
                'verbose_name_plural': 'Domains',
                'db_table': 'services_domains',
            },
        ),
        migrations.CreateModel(
            name='BusinessRegistration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subscription_id', models.CharField(max_length=64)),
                ('business_name', models.CharField(max_length=256)),
                ('business_delegation', models.CharField(choices=[('Co', 'Co'), ('CO', 'CO'), ('Co.', 'Co.'), ('CO.', 'CO.'), ('Companies', 'Companies'), ('COMPANIES', 'COMPANIES'), ('Company', 'Company'), ('Corp', 'Corp'), ('CORP', 'CORP'), ('Corp.', 'Corp.'), ('CORP.', 'CORP.'), ('Corporation', 'Corporation'), ('CORPORATION', 'CORPORATION'), ('Corporations', 'Corporations'), ('CORPORATIONS', 'CORPORATIONS'), ('Inc', 'Inc'), ('INC', 'INC'), ('Inc.', 'Inc.'), ('INC.', 'INC.'), ('Incorporated', 'Incorporated'), ('INCORPORATED', 'INCORPORATED'), ('Limited', 'Limited'), ('LIMITED', 'LIMITED'), ('Ltd', 'Ltd'), ('LTD', 'LTD'), ('Ltd.', 'Ltd.'), ('LTD.', 'LTD.'), ('LLC', 'LLC'), ('COOP', 'COOP'), ('Cooperative', 'Cooperative'), ('COOPERATIVE', 'COOPERATIVE'), ('L. L. C.', 'L. L. C.'), ('L.L.C.', 'L.L.C.'), ('Limited Liability Company', 'Limited Liability Company'), ('LIMITED LIABILITY COMPANY', 'LIMITED LIABILITY COMPANY'), ('LLC', 'LLC'), ('L. L. P.', 'L. L. P.'), ('L.L.P.', 'L.L.P.'), ('Limited Liability Partnership', 'Limited Liability Partnership'), ('LLP', 'LLP'), ('R. L. L. P.', 'R. L. L. P.'), ('R.L.L.P.', 'R.L.L.P.'), ('Registered Limited Liability Partnership', 'Registered Limited Liability Partnership'), ('REGISTERED LIMITED LIABILITY PARTNERSHIP', 'REGISTERED LIMITED LIABILITY PARTNERSHIP'), ('RLLP', 'RLLP'), ('L P', 'L P'), ('L. P.', 'L. P.'), ('L.P.', 'L.P.'), ('Limited Partnership', 'Limited Partnership'), ('LIMITED PARTNERSHIP', 'LIMITED PARTNERSHIP'), ('LP', 'LP')], max_length=128)),
                ('state_of_registration', models.CharField(choices=[('Alabama', 'AL'), ('Alaska', 'AK'), ('Arkansas', 'AR'), ('California', 'CA'), ('Colorado', 'CO'), ('Connecticut', 'CT'), ('Delaware', 'DL'), ('Florida', 'FL'), ('Georgia', 'GA'), ('Hawaii', 'HI'), ('Idaho', 'ID'), ('Illinois', 'IL'), ('Indiana', 'IN'), ('Iowa', 'IA'), ('Kansas', 'KS'), ('Kentucky', 'KY'), ('Louisiana', 'LA'), ('Maine', 'ME'), ('Maryland', 'MD'), ('Massachussets', 'MA'), ('Michigan', 'MI'), ('Minnesota', 'MN'), ('Mississippi', 'MS'), ('Missouri', 'MO'), ('Montana', 'MT'), ('Nebraska', 'NE'), ('Nevada', 'NV'), ('New Hampshire', 'NH'), ('New Jersey', 'NJ'), ('New Mexico', 'NM'), ('New York', 'NY'), ('North Carolina', 'NC'), ('North Dakota', 'ND'), ('Ohio', 'OH'), ('Oklahoma', 'OK'), ('Oregon', 'OR'), ('Pennsylvania', 'PA'), ('Rhode Island', 'RI'), ('South Carolina', 'SC'), ('South Dakota', 'SD'), ('Tennessee', 'TN'), ('Texas', 'TX'), ('Utah', 'UT'), ('Vermont', 'VT'), ('Virginia', 'VA'), ('Washington', 'WA'), ('West Virginia', 'WV'), ('Wisconsin', 'WI'), ('Wyoming', 'WY')], max_length=64)),
                ('outstanding_shares', models.IntegerField(blank=True, default=0, null=True)),
                ('business_owners', models.JSONField(default=dict)),
                ('business_addresses', models.JSONField(default=dict)),
                ('incorporators', models.JSONField(default=dict)),
                ('registered_agent', models.CharField(max_length=256)),
                ('registered_agent_address', models.JSONField(default=dict)),
                ('incorporation_document', models.FileField(blank=True, upload_to='services/organizations/registrations/%Y/%m/%d/')),
                ('registration_date', models.DateField(auto_now_add=True)),
                ('renewal_date', models.DateField()),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='organizations.organization')),
            ],
            options={
                'verbose_name': 'Business Registration',
                'verbose_name_plural': 'Business Registrations',
                'db_table': 'services_business_registration',
            },
        ),
        migrations.CreateModel(
            name='BusinessOwner',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=256)),
                ('middle_name', models.CharField(blank=True, max_length=256)),
                ('last_name', models.CharField(max_length=256)),
                ('email', models.EmailField(blank=True, max_length=256)),
                ('phone', phonenumber_field.modelfields.PhoneNumberField(blank=True, max_length=128, null=True, region=None)),
                ('address', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.RESTRICT, to='services.businessowneraddress')),
            ],
        ),
    ]
